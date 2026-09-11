use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
};

use anyhow::{Context, Result, bail};
use serde_json::Value;

const JSON_PATH: &str = "docs/distribution-roadmap.json";
const MARKDOWN_PATH: &str = "docs/distribution-roadmap.md";
const SCHEMA_VERSION: &str = "1.0";

fn main() -> Result<()> {
    let mode = env::args().nth(1).unwrap_or_else(|| "--check".into());
    if !matches!(mode.as_str(), "--check" | "--write" | "--help") {
        bail!("usage: cargo run --bin validate_distribution_roadmap -- [--check|--write]");
    }
    if mode == "--help" {
        println!("validate or regenerate the distribution roadmap");
        println!("  --check  validate JSON and require synchronized Markdown (default)");
        println!("  --write  validate JSON and regenerate Markdown");
        return Ok(());
    }

    let root = env::current_dir().context("resolve repository root")?;
    let json_path = root.join(JSON_PATH);
    let markdown_path = root.join(MARKDOWN_PATH);
    let json_text =
        fs::read_to_string(&json_path).with_context(|| format!("read {}", json_path.display()))?;
    let roadmap: Value = serde_json::from_str(&json_text)
        .with_context(|| format!("parse {}", json_path.display()))?;
    validate(&roadmap)?;
    let rendered = render(&roadmap)?;

    if mode == "--write" {
        fs::write(&markdown_path, rendered)
            .with_context(|| format!("write {}", markdown_path.display()))?;
        println!("validated {JSON_PATH} and regenerated {MARKDOWN_PATH}");
    } else {
        let existing = fs::read_to_string(&markdown_path)
            .with_context(|| format!("read {}", markdown_path.display()))?;
        if existing != rendered {
            bail!(
                "{MARKDOWN_PATH} is out of sync; run cargo run --bin validate_distribution_roadmap -- --write"
            );
        }
        println!("validated {JSON_PATH} and synchronized {MARKDOWN_PATH}");
    }
    Ok(())
}

fn validate(roadmap: &Value) -> Result<()> {
    let object = roadmap
        .as_object()
        .context("roadmap root must be a JSON object")?;
    let schema_version = required_string(object, "schema_version")?;
    if schema_version != SCHEMA_VERSION {
        bail!("unsupported schema_version {schema_version:?}");
    }
    let revision = object
        .get("roadmap_revision")
        .and_then(Value::as_u64)
        .context("roadmap_revision must be a positive integer")?;
    if revision == 0 {
        bail!("roadmap_revision must be positive");
    }
    let commit = required_string(object, "inspected_source_commit")?;
    if commit.len() != 40 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("inspected_source_commit must be a full 40-character hexadecimal SHA");
    }
    for field in [
        "repository",
        "source_branch",
        "roadmap_branch",
        "overall_objective",
        "current_milestone",
        "next_executable_task",
    ] {
        required_string(object, field)?;
    }
    for field in [
        "scope",
        "non_goals",
        "blockers",
        "operating_rules",
        "milestones",
    ] {
        required_array(object, field)?;
    }

    let mut milestone_ids = BTreeSet::new();
    let mut task_ids = BTreeSet::new();
    let mut task_dependencies = BTreeMap::new();
    let milestones = required_array(object, "milestones")?;
    if milestones.is_empty() {
        bail!("milestones must not be empty");
    }
    for milestone in milestones {
        let milestone = milestone
            .as_object()
            .context("each milestone must be an object")?;
        let milestone_id = required_string(milestone, "id")?;
        if !milestone_ids.insert(milestone_id.to_owned()) {
            bail!("duplicate milestone id {milestone_id}");
        }
        required_string(milestone, "title")?;
        validate_status(required_string(milestone, "status")?, "milestone")?;
        required_string(milestone, "objective")?;
        let tasks = milestone
            .get("tasks")
            .and_then(Value::as_array)
            .with_context(|| format!("milestone {milestone_id} tasks must be an array"))?;
        if tasks.is_empty() {
            bail!("milestone {milestone_id} must contain tasks");
        }
        for task in tasks {
            let task = task
                .as_object()
                .with_context(|| format!("tasks in {milestone_id} must be objects"))?;
            let task_id = required_string(task, "id")?;
            if !task_ids.insert(task_id.to_owned()) {
                bail!("duplicate task id {task_id}");
            }
            for field in [
                "objective",
                "user_visible_outcome",
                "status",
                "dependencies",
                "expected_implementation_areas",
                "deliverables",
                "validation",
                "completion_evidence",
                "risks_or_unresolved_decisions",
                "requirements",
            ] {
                if !task.contains_key(field) {
                    bail!("task {task_id} is missing {field}");
                }
            }
            validate_status(required_string(task, "status")?, "task")?;
            let dependencies = string_array(task, "dependencies")?;
            task_dependencies.insert(task_id.to_owned(), dependencies);
            for field in [
                "deliverables",
                "validation",
                "completion_evidence",
                "risks_or_unresolved_decisions",
            ] {
                string_array(task, field)?;
            }
            validate_areas(task.get("expected_implementation_areas").unwrap(), task_id)?;
            validate_requirements(task.get("requirements").unwrap(), task_id)?;
            if required_string(task, "status")? == "completed"
                && string_array(task, "completion_evidence")?.is_empty()
            {
                bail!("completed task {task_id} must contain completion_evidence");
            }
        }
    }

    let current_milestone = required_string(object, "current_milestone")?;
    if !milestone_ids.contains(current_milestone) {
        bail!("current_milestone {current_milestone} does not exist");
    }
    let next_task = required_string(object, "next_executable_task")?;
    if !task_ids.contains(next_task) {
        bail!("next_executable_task {next_task} does not exist");
    }
    for (task_id, dependencies) in &task_dependencies {
        for dependency in dependencies {
            if !task_ids.contains(dependency) {
                bail!("task {task_id} has unknown dependency {dependency}");
            }
        }
    }
    detect_cycles(&task_dependencies)?;
    validate_blockers(object.get("blockers").unwrap())?;
    validate_strings(object, "scope")?;
    validate_strings(object, "non_goals")?;
    validate_strings(object, "operating_rules")?;
    reject_private_evidence(roadmap)?;
    Ok(())
}

fn validate_status(status: &str, kind: &str) -> Result<()> {
    if matches!(status, "planned" | "in_progress" | "blocked" | "completed") {
        Ok(())
    } else {
        bail!("invalid {kind} status {status:?}")
    }
}

fn validate_areas(value: &Value, task_id: &str) -> Result<()> {
    let areas = value.as_array().with_context(|| {
        format!("task {task_id} expected_implementation_areas must be an array")
    })?;
    if areas.is_empty() {
        bail!("task {task_id} must name implementation areas");
    }
    for area in areas {
        let area = area
            .as_object()
            .with_context(|| format!("task {task_id} implementation areas must be objects"))?;
        required_string(area, "path")?;
        required_string(area, "purpose")?;
        let kind = required_string(area, "kind")?;
        if !matches!(kind, "existing" | "planned" | "workflow") {
            bail!("task {task_id} has invalid implementation area kind {kind:?}");
        }
    }
    Ok(())
}

fn validate_requirements(value: &Value, task_id: &str) -> Result<()> {
    let requirements = value
        .as_object()
        .with_context(|| format!("task {task_id} requirements must be an object"))?;
    for field in [
        "native_windows",
        "native_linux",
        "github_access",
        "human_action",
    ] {
        if !requirements.get(field).is_some_and(Value::is_boolean) {
            bail!("task {task_id} requirement {field} must be boolean");
        }
    }
    Ok(())
}

fn validate_blockers(value: &Value) -> Result<()> {
    for blocker in value.as_array().context("blockers must be an array")? {
        let blocker = blocker.as_object().context("blockers must be objects")?;
        required_string(blocker, "id")?;
        validate_status(required_string(blocker, "status")?, "blocker")?;
        required_string(blocker, "description")?;
        string_array(blocker, "unblocks")?;
    }
    Ok(())
}

fn detect_cycles(dependencies: &BTreeMap<String, Vec<String>>) -> Result<()> {
    fn visit(
        task: &str,
        dependencies: &BTreeMap<String, Vec<String>>,
        visiting: &mut BTreeSet<String>,
        visited: &mut BTreeSet<String>,
    ) -> Result<()> {
        if visited.contains(task) {
            return Ok(());
        }
        if !visiting.insert(task.to_owned()) {
            bail!("dependency cycle includes {task}");
        }
        for dependency in dependencies.get(task).into_iter().flatten() {
            visit(dependency, dependencies, visiting, visited)?;
        }
        visiting.remove(task);
        visited.insert(task.to_owned());
        Ok(())
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for task in dependencies.keys() {
        visit(task, dependencies, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn reject_private_evidence(roadmap: &Value) -> Result<()> {
    let text = serde_json::to_string(roadmap)?;
    for marker in [
        "-----BEGIN",
        "Bearer ",
        "C:\\Users\\",
        "C:/Users/",
        "/Users/",
        "/home/",
        "CODEX_AUTOAPPROVER_SESSION_TOKEN",
        "CODEX_AUTOAPPROVER_SESSION_SECRET",
    ] {
        if text.contains(marker) {
            bail!("roadmap contains prohibited private or secret marker {marker:?}");
        }
    }
    Ok(())
}

fn required_string<'a>(object: &'a serde_json::Map<String, Value>, field: &str) -> Result<&'a str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("{field} must be a non-empty string"))
}

fn required_array<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a [Value]> {
    object
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .with_context(|| format!("{field} must be an array"))
}

fn string_array(object: &serde_json::Map<String, Value>, field: &str) -> Result<Vec<String>> {
    object
        .get(field)
        .and_then(Value::as_array)
        .with_context(|| format!("{field} must be an array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .with_context(|| format!("{field} must contain non-empty strings"))
        })
        .collect()
}

fn validate_strings(object: &serde_json::Map<String, Value>, field: &str) -> Result<()> {
    string_array(object, field).map(|_| ())
}

fn render(roadmap: &Value) -> Result<String> {
    let object = roadmap
        .as_object()
        .context("roadmap root must be an object")?;
    let mut markdown = String::from(
        "<!-- Generated from docs/distribution-roadmap.json by validate_distribution_roadmap; do not edit. -->\n\n# Distribution roadmap\n\n",
    );
    markdown.push_str(&format!(
        "- Schema version: `{}`\n- Roadmap revision: `{}`\n- Repository: `{}`\n- Inspected source commit: `{}`\n- Source branch: `{}`\n- Roadmap branch: `{}`\n- Current milestone: `{}`\n- Next executable task: `{}`\n\n",
        required_string(object, "schema_version")?,
        object
            .get("roadmap_revision")
            .and_then(Value::as_u64)
            .context("roadmap_revision")?,
        required_string(object, "repository")?,
        required_string(object, "inspected_source_commit")?,
        required_string(object, "source_branch")?,
        required_string(object, "roadmap_branch")?,
        required_string(object, "current_milestone")?,
        required_string(object, "next_executable_task")?,
    ));
    section_text(
        &mut markdown,
        "Objective",
        required_string(object, "overall_objective")?,
    );
    section_list(&mut markdown, "Scope", string_array(object, "scope")?);
    section_list(
        &mut markdown,
        "Non-goals",
        string_array(object, "non_goals")?,
    );

    markdown.push_str("## Blockers\n\n");
    for blocker in required_array(object, "blockers")? {
        let blocker = blocker.as_object().context("blocker object")?;
        markdown.push_str(&format!(
            "### `{}`\n\n- Status: `{}`\n- Description: {}\n- Unblocks: {}\n\n",
            required_string(blocker, "id")?,
            required_string(blocker, "status")?,
            required_string(blocker, "description")?,
            display_list(string_array(blocker, "unblocks")?),
        ));
    }
    section_list(
        &mut markdown,
        "Operating rules",
        string_array(object, "operating_rules")?,
    );

    markdown.push_str("## Milestones\n\n");
    for milestone in required_array(object, "milestones")? {
        let milestone = milestone.as_object().context("milestone object")?;
        markdown.push_str(&format!(
            "### {} — {}\n\n- Status: `{}`\n- Objective: {}\n\n",
            required_string(milestone, "id")?,
            required_string(milestone, "title")?,
            required_string(milestone, "status")?,
            required_string(milestone, "objective")?,
        ));
        for task in milestone
            .get("tasks")
            .and_then(Value::as_array)
            .context("milestone tasks")?
        {
            render_task(&mut markdown, task.as_object().context("task object")?)?;
        }
    }

    let validation = object
        .get("validation_contract")
        .and_then(Value::as_object)
        .context("validation_contract must be an object")?;
    markdown.push_str("## Roadmap validation contract\n\n");
    markdown.push_str(&format!("{}\n\n", required_string(validation, "purpose")?));
    for item in string_array(validation, "checks")? {
        markdown.push_str(&format!("- {item}\n"));
    }
    Ok(format!("{}\n", markdown.trim_end()))
}

fn render_task(markdown: &mut String, task: &serde_json::Map<String, Value>) -> Result<()> {
    let id = required_string(task, "id")?;
    markdown.push_str(&format!(
        "#### {} — {}\n\n- Status: `{}`\n- Dependencies: {}\n- Objective: {}\n- User-visible outcome: {}\n\n",
        id,
        task.get("title").and_then(Value::as_str).unwrap_or(id),
        required_string(task, "status")?,
        display_list(string_array(task, "dependencies")?),
        required_string(task, "objective")?,
        required_string(task, "user_visible_outcome")?,
    ));
    markdown.push_str("**Expected implementation areas**\n\n");
    for area in task
        .get("expected_implementation_areas")
        .and_then(Value::as_array)
        .context("implementation areas")?
    {
        let area = area.as_object().context("implementation area")?;
        markdown.push_str(&format!(
            "- `{}` (`{}`): {}\n",
            required_string(area, "path")?,
            required_string(area, "kind")?,
            required_string(area, "purpose")?,
        ));
    }
    markdown.push_str("\n**Deliverables**\n\n");
    for item in string_array(task, "deliverables")? {
        markdown.push_str(&format!("- {item}\n"));
    }
    markdown.push_str("\n**Validation**\n\n");
    for item in string_array(task, "validation")? {
        markdown.push_str(&format!("- {item}\n"));
    }
    markdown.push_str("\n**Completion evidence**\n\n");
    let evidence = string_array(task, "completion_evidence")?;
    if evidence.is_empty() {
        markdown.push_str(
            "- Not complete; evidence must be recorded before status becomes `completed`.\n",
        );
    } else {
        for item in evidence {
            markdown.push_str(&format!("- {item}\n"));
        }
    }
    markdown.push_str("\n**Risks and unresolved decisions**\n\n");
    for item in string_array(task, "risks_or_unresolved_decisions")? {
        markdown.push_str(&format!("- {item}\n"));
    }
    let requirements = task
        .get("requirements")
        .and_then(Value::as_object)
        .context("requirements")?;
    markdown.push_str("\n**Required access or action**\n\n");
    for (key, label) in [
        ("native_windows", "Native Windows"),
        ("native_linux", "Native Linux"),
        ("github_access", "GitHub access"),
        ("human_action", "Human action"),
    ] {
        markdown.push_str(&format!(
            "- {label}: `{}`\n",
            requirements
                .get(key)
                .and_then(Value::as_bool)
                .context("boolean requirement")?
        ));
    }
    markdown.push('\n');
    Ok(())
}

fn section_text(markdown: &mut String, title: &str, text: &str) {
    markdown.push_str(&format!("## {title}\n\n{text}\n\n"));
}

fn section_list(markdown: &mut String, title: &str, values: Vec<String>) {
    markdown.push_str(&format!("## {title}\n\n"));
    for value in values {
        markdown.push_str(&format!("- {value}\n"));
    }
    markdown.push('\n');
}

fn display_list(values: Vec<String>) -> String {
    if values.is_empty() {
        "none".into()
    } else {
        values
            .into_iter()
            .map(|value| format!("`{value}`"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}
