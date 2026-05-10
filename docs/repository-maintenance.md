# Repository maintenance

这个项目是 ESP-IDF/CMake 工程，仓库里应只保留源码、配置、文档和必要资源。以下内容不要提交：

- `build*/`、`CMakeFiles/`、`compile_commands.json`、`*.elf`、`*.map`
- `managed_components/`、本地 `components/` 缓存
- `sdkconfig`、`dependencies.lock`
- `.run/`、`*.log`、`.env`
- `main/assets/lang_config.h`，它会由 `scripts/gen_lang.py` 在构建时生成

## 清理当前提交

如果本地又误跟踪了生成文件，先检查：

```powershell
git ls-files -ci --exclude-standard
```

把这些文件从 Git 索引移除，但保留本地文件：

```powershell
git rm --cached -r -- .run build build.bak_* managed_components dependencies.lock main/assets/lang_config.h
git status --short
```

之后正常提交 `.gitignore` 和删除记录即可。

## 清理 GitHub 历史体积

如果大文件已经推到 GitHub，仅在新提交里删除它们不会缩小历史体积。需要重写历史，然后强推。操作前请确认所有协作者都知道这件事，并保留备份分支或镜像。

推荐使用 `git-filter-repo`：

```powershell
python -m pip install git-filter-repo
git filter-repo --path build --path managed_components --path-glob "build.bak_*" --invert-paths
git push --force-with-lease origin main
```

强推后，其他克隆需要重新克隆，或按团队约定重置到新的 `main` 历史。
