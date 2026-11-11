import collections, json, pathlib, re, sys, zipfile
import yaml

root = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
plugins = []
findings = []
log_counts = collections.Counter()
patterns = {
    "missing_dependency": r"UnknownDependencyException|missing dependency",
    "load_error": r"Could not load|Error occurred while enabling|Failed to load",
    "java_mismatch": r"UnsupportedClassVersionError",
    "class_missing": r"ClassNotFoundException|NoClassDefFoundError",
    "api_mismatch": r"NoSuchMethodError|NoSuchFieldError",
    "database": r"SQLException|Communications link failure|Access denied for user",
    "port": r"Address already in use",
}
skip = {"world", "world_nether", "world_the_end", "libraries", "cache", "backups", ".git"}
def files():
    for p in root.rglob("*"):
        if p.is_file() and not any(part in skip for part in p.relative_to(root).parts):
            yield p

for p in files():
    rel = str(p.relative_to(root))
    if p.suffix.lower() == ".jar":
        obj = {"path":rel, "name":p.stem, "version":"unknown", "platform":"unknown", "depends":[]}
        try:
            with zipfile.ZipFile(p) as z:
                names = set(z.namelist())
                if "velocity-plugin.json" in names:
                    obj["platform"] = "velocity"
                    data = json.loads(z.read("velocity-plugin.json"))
                    obj["name"] = str(data.get("id", p.stem))
                    obj["version"] = str(data.get("version", "unknown"))
                    obj["depends"] = [str(d.get("id")) for d in data.get("dependencies", []) if isinstance(d, dict) and not d.get("optional")]
                else:
                    f = next((n for n in ("plugin.yml", "paper-plugin.yml", "bungee.yml") if n in names), None)
                    if f:
                        obj["platform"] = f
                        data = yaml.safe_load(z.read(f)) or {}
                        obj["name"] = str(data.get("name", p.stem))
                        obj["version"] = str(data.get("version", "unknown"))
                        obj["depends"] = list(data.get("depend") or [])
                        if f == "paper-plugin.yml":
                            for group in ("bootstrap", "server"):
                                for k, v in (data.get("dependencies", {}).get(group, {}) or {}).items():
                                    if not isinstance(v, dict) or v.get("required", True):
                                        obj["depends"].append(k)
        except Exception as e:
            findings.append({"type":"unreadable_jar", "path":rel, "detail":type(e).__name__})
        plugins.append(obj)
    elif p.suffix.lower() in (".json", ".yml", ".yaml") and p.stat().st_size < 1000000 and len(findings) < 2000:
        try:
            if p.suffix.lower() == ".json":
                json.loads(p.read_text(encoding="utf-8-sig"))
            else:
                yaml.safe_load(p.read_text(encoding="utf-8-sig"))
        except Exception as e:
            findings.append({"type":"invalid_config", "path":rel, "detail":type(e).__name__})
    elif p.name == "latest.log" and p.stat().st_size < 200000000:
        with p.open(errors="replace") as f:
            for i, line in enumerate(f):
                if i > 300000: break
                for category, pattern in patterns.items():
                    if re.search(pattern, line, re.I):
                        log_counts[category] += 1

scopes = collections.defaultdict(list)
for obj in plugins:
    parts = pathlib.PurePosixPath(obj["path"]).parts
    if "plugins" in parts:
        scopes["/".join(parts[:parts.index("plugins")+1])].append(obj)
for scope, members in scopes.items():
    names = collections.Counter(p["name"].lower() for p in members)
    for name, count in names.items():
        if count > 1:
            findings.append({"type":"duplicate_plugin", "path":scope, "detail":name})
    for member in members:
        for dep in member["depends"]:
            if str(dep).lower() not in names:
                findings.append({"type":"missing_dependency", "path":member["path"], "detail":str(dep)})
result = {"plugins":plugins, "findings":findings, "log_error_counts":dict(log_counts)}
(out / "audit.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
lines = ["# EVERNIGHT NETWORK — статический аудит", "", "JAR: "+str(len(plugins)), "Замечаний: "+str(len(findings)), "", "## Замечания"]
for x in findings:
    lines.append("- "+x["type"]+": "+x["path"]+" — "+x["detail"])
lines.extend(["", "## JAR", "", "| File | Plugin | Version | Dependencies |", "|---|---|---|---|"])
for p in plugins:
    lines.append("| "+p["path"].replace("|","/")+" | "+p["name"].replace("|","/")+" | "+p["version"].replace("|","/")+" | "+", ".join(p["depends"]).replace("|","/")+" |")
lines.extend(["", "## Ошибки логов (только категории и количество)"])
for name, count in log_counts.items():
    lines.append("- "+name+": "+str(count))
lines.extend(["", "Это статическая проверка, а не тест успешного запуска Paper/Velocity."])
summary = "\n".join(lines)+"\n"
(out / "AUDIT.md").write_text(summary, encoding="utf-8")
print("Analyzed", len(plugins), "JARs, found", len(findings), "issues.")
