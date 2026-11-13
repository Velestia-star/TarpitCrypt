"""TarpitCrypt 前端静态资源包（打包载体，无运行时逻辑）。

`docs/` 同时承担两个职责：

1. GitHub Pages 的发布源（`main /docs`），浏览器直接加载 index.html
   与同目录的 JS / CSS / vendor 资源；
2. Python 发行包里的静态资源。`tarpitcrypt_server.py` 用
   ``Path(__file__).parent / "docs"`` 定位前端，pip 安装后该路径指向
   ``site-packages/docs``，因此这里必须有 `__init__.py` 让 setuptools
   把整个目录当作包收进 wheel，并由 `package-data` 带上非 .py 资源。

这个模块刻意保持空实现：页面永远不会 import 它，导入也不应产生副作用。
Pages 会把它当成一个普通静态文件发布，内容仅为注释，无影响。
"""
