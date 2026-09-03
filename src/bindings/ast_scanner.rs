use crate::bindings::types::{AccessKind, BindingAccess};
use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_parser::Parser;
use oxc_span::{SourceType, Span};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Index to convert byte offsets into 1-based line and column numbers.
pub struct LineIndex {
    line_starts: Vec<usize>,
}

impl LineIndex {
    pub fn new(source: &str) -> Self {
        let mut line_starts = vec![0];
        for (i, byte) in source.bytes().enumerate() {
            if byte == b'\n' {
                line_starts.push(i + 1);
            }
        }
        Self { line_starts }
    }

    pub fn line_col(&self, byte_offset: usize) -> (usize, usize) {
        match self.line_starts.binary_search(&byte_offset) {
            Ok(idx) => (idx + 1, 1),
            Err(idx) => {
                let line = idx; // 1-based line
                let line_start = self.line_starts[idx - 1];
                let col = byte_offset.saturating_sub(line_start) + 1;
                (line, col)
            }
        }
    }
}

/// Scanner that walks an AST to collect all Cloudflare binding references.
pub struct AstScanner<'a> {
    file_path: &'a str,
    #[allow(dead_code)]
    source_text: &'a str,
    line_index: LineIndex,
    ignore_lines: HashSet<usize>,
    accesses: Vec<BindingAccess>,
}

impl<'a> AstScanner<'a> {
    pub fn new(file_path: &'a str, source_text: &'a str) -> Self {
        let line_index = LineIndex::new(source_text);
        let mut ignore_lines = HashSet::new();

        // Scan for // cf-ignore or // cf-binding-ignore comments
        for (idx, line) in source_text.lines().enumerate() {
            let line_num = idx + 1;
            if line.contains("cf-ignore") || line.contains("cf-binding-ignore") {
                ignore_lines.insert(line_num);
                ignore_lines.insert(line_num + 1); // Also ignore next line
            }
        }

        Self {
            file_path,
            source_text,
            line_index,
            ignore_lines,
            accesses: Vec::new(),
        }
    }

    pub fn scan_program(&mut self, program: &Program) -> Vec<BindingAccess> {
        for stmt in &program.body {
            self.walk_statement(stmt);
        }
        self.accesses.clone()
    }

    fn record_access(&mut self, name: &str, span: Span, kind: AccessKind, raw_expr: &str) {
        let (line, column) = self.line_index.line_col(span.start as usize);
        if self.ignore_lines.contains(&line) {
            return;
        }

        // Avoid common false positives / standard JS built-ins
        if name.is_empty()
            || name == "undefined"
            || name == "null"
            || name == "prototype"
            || name == "constructor"
            || name == "length"
            || name == "toString"
            || name == "valueOf"
        {
            return;
        }

        self.accesses.push(BindingAccess {
            name: name.to_string(),
            file_path: self.file_path.to_string(),
            line,
            column,
            raw_expression: raw_expr.to_string(),
            access_kind: kind,
        });
    }

    // ==========================================
    // AST Walkers
    // ==========================================

    fn walk_block_statement(&mut self, b: &BlockStatement) {
        for s in &b.body {
            self.walk_statement(s);
        }
    }

    fn walk_statement(&mut self, stmt: &Statement) {
        match stmt {
            Statement::BlockStatement(b) => {
                self.walk_block_statement(b);
            }
            Statement::ExpressionStatement(e) => {
                self.walk_expression(&e.expression);
            }
            Statement::IfStatement(s) => {
                self.walk_expression(&s.test);
                self.walk_statement(&s.consequent);
                if let Some(alt) = &s.alternate {
                    self.walk_statement(alt);
                }
            }
            Statement::DoWhileStatement(s) => {
                self.walk_statement(&s.body);
                self.walk_expression(&s.test);
            }
            Statement::WhileStatement(s) => {
                self.walk_expression(&s.test);
                self.walk_statement(&s.body);
            }
            Statement::ForStatement(s) => {
                if let Some(init) = &s.init {
                    match init {
                        ForStatementInit::VariableDeclaration(d) => {
                            self.walk_variable_declaration(d)
                        }
                        _ => {
                            if let Some(e) = init.as_expression() {
                                self.walk_expression(e);
                            }
                        }
                    }
                }
                if let Some(test) = &s.test {
                    self.walk_expression(test);
                }
                if let Some(update) = &s.update {
                    self.walk_expression(update);
                }
                self.walk_statement(&s.body);
            }
            Statement::ForInStatement(s) => {
                self.walk_expression(&s.right);
                self.walk_statement(&s.body);
            }
            Statement::ForOfStatement(s) => {
                self.walk_expression(&s.right);
                self.walk_statement(&s.body);
            }
            Statement::ReturnStatement(s) => {
                if let Some(arg) = &s.argument {
                    self.walk_expression(arg);
                }
            }
            Statement::SwitchStatement(s) => {
                self.walk_expression(&s.discriminant);
                for case in &s.cases {
                    if let Some(test) = &case.test {
                        self.walk_expression(test);
                    }
                    for c_stmt in &case.consequent {
                        self.walk_statement(c_stmt);
                    }
                }
            }
            Statement::ThrowStatement(s) => {
                self.walk_expression(&s.argument);
            }
            Statement::TryStatement(s) => {
                self.walk_block_statement(&s.block);
                if let Some(handler) = &s.handler {
                    self.walk_block_statement(&handler.body);
                }
                if let Some(finalizer) = &s.finalizer {
                    self.walk_block_statement(finalizer);
                }
            }
            Statement::VariableDeclaration(d) => {
                self.walk_variable_declaration(d);
            }
            Statement::FunctionDeclaration(f) => {
                let name = f.id.as_ref().map(|id| id.name.as_str());
                self.walk_function(f, name);
            }
            Statement::ClassDeclaration(c) => {
                self.walk_class(c);
            }
            Statement::ExportDeclaration(d) => {
                self.walk_declaration(&d.declaration);
            }
            Statement::ExportDefaultDeclaration(d) => match &d.declaration {
                ExportDefaultDeclarationKind::FunctionDeclaration(f) => {
                    let name = f.id.as_ref().map(|id| id.name.as_str());
                    self.walk_function(f, name);
                }
                ExportDefaultDeclarationKind::ClassDeclaration(c) => {
                    self.walk_class(c);
                }
                _ => {
                    if let Some(expr) = d.declaration.as_expression() {
                        self.walk_expression(expr);
                    }
                }
            },
            _ => {}
        }
    }

    fn walk_declaration(&mut self, decl: &Declaration) {
        match decl {
            Declaration::VariableDeclaration(d) => self.walk_variable_declaration(d),
            Declaration::FunctionDeclaration(f) => {
                let name = f.id.as_ref().map(|id| id.name.as_str());
                self.walk_function(f, name);
            }
            Declaration::ClassDeclaration(c) => self.walk_class(c),
            _ => {}
        }
    }

    fn walk_variable_declaration(&mut self, decl: &VariableDeclaration) {
        for declarator in &decl.declarations {
            let var_name = if let BindingPattern::BindingIdentifier(ident) = &declarator.id {
                Some(ident.name.as_str())
            } else {
                None
            };

            if let Some(init) = &declarator.init {
                // Check if init is an env source: const { KV_1, KV_2 } = env;
                if let Some(env_expr_str) = is_env_source(init) {
                    if let BindingPattern::ObjectPattern(obj) = &declarator.id {
                        for prop in &obj.properties {
                            if let Some(name) = prop.key.name() {
                                let raw = format!("const {{ {} }} = {}", name, env_expr_str);
                                self.record_access(
                                    &name,
                                    prop.span,
                                    AccessKind::Destructured,
                                    &raw,
                                );
                            }
                        }
                    }
                } else if is_process_env(init)
                    && let BindingPattern::ObjectPattern(obj) = &declarator.id
                {
                    for prop in &obj.properties {
                        if let Some(name) = prop.key.name() {
                            let raw = format!("const {{ {} }} = process.env", name);
                            self.record_access(&name, prop.span, AccessKind::ProcessEnv, &raw);
                        }
                    }
                }

                match init {
                    Expression::ArrowFunctionExpression(f) => {
                        self.walk_arrow_function(f, var_name);
                    }
                    Expression::FunctionExpression(f) => {
                        self.walk_function(f, var_name);
                    }
                    _ => {
                        self.walk_expression(init);
                    }
                }
            }
        }
    }

    fn walk_function(&mut self, func: &Function, func_name: Option<&str>) {
        let is_worker_handler = func_name.is_some_and(|name| {
            matches!(
                name,
                "fetch"
                    | "scheduled"
                    | "queue"
                    | "email"
                    | "tail"
                    | "trace"
                    | "onRequest"
                    | "onRequestGet"
                    | "onRequestPost"
                    | "onRequestPut"
                    | "onRequestDelete"
            )
        });

        for (param_idx, param) in func.params.items.iter().enumerate() {
            if let BindingPattern::ObjectPattern(obj) = &param.pattern {
                for prop in &obj.properties {
                    if let Some(prop_name) = prop.key.name() {
                        if prop_name == "env" {
                            if let BindingPattern::ObjectPattern(nested_obj) = &prop.value {
                                for nested_prop in &nested_obj.properties {
                                    if let Some(nested_name) = nested_prop.key.name() {
                                        let raw = format!("{{ env: {{ {} }} }}", nested_name);
                                        self.record_access(
                                            &nested_name,
                                            nested_prop.span,
                                            AccessKind::ParamDestructured,
                                            &raw,
                                        );
                                    }
                                }
                            }
                        } else if (param_idx == 1
                            && (is_worker_handler || func.params.items.len() >= 2))
                            || (param_idx == 0 && is_worker_handler)
                        {
                            let raw = format!("handler(req, {{ {} }}, ctx)", prop_name);
                            self.record_access(
                                &prop_name,
                                prop.span,
                                AccessKind::ParamDestructured,
                                &raw,
                            );
                        }
                    }
                }
            }
        }

        if let Some(body) = &func.body {
            for stmt in &body.statements {
                self.walk_statement(stmt);
            }
        }
    }

    fn walk_class(&mut self, class: &Class) {
        for element in &class.body.body {
            match element {
                ClassElement::MethodDefinition(m) => {
                    let name = m.key.name();
                    self.walk_function(&m.value, name.as_deref());
                }
                ClassElement::PropertyDefinition(p) => {
                    if let Some(val) = &p.value {
                        self.walk_expression(val);
                    }
                }
                _ => {}
            }
        }
    }

    fn walk_expression(&mut self, expr: &Expression) {
        match expr {
            // Check direct property access: env.MY_KV or c.env.DB or Astro.locals.runtime.env.AI
            Expression::StaticMemberExpression(m) => {
                if let Some(env_expr_str) = is_env_source(&m.object) {
                    let prop_name = m.property.name.as_str();
                    let raw = format!("{}.{}", env_expr_str, prop_name);
                    self.record_access(prop_name, m.span, AccessKind::DirectMember, &raw);
                    return;
                } else if is_process_env(&m.object) {
                    let prop_name = m.property.name.as_str();
                    let raw = format!("process.env.{}", prop_name);
                    self.record_access(prop_name, m.span, AccessKind::ProcessEnv, &raw);
                    return;
                }
                self.walk_expression(&m.object);
            }

            // Check computed property access: env["MY_KV"] or c.env['DB'] or process.env["API_KEY"]
            Expression::ComputedMemberExpression(m) => {
                if let Some(env_expr_str) = is_env_source(&m.object) {
                    if let Some(prop_name) = extract_string_literal(&m.expression) {
                        let raw = format!("{}[\"{}\"]", env_expr_str, prop_name);
                        self.record_access(&prop_name, m.span, AccessKind::DirectMember, &raw);
                        return;
                    }
                } else if is_process_env(&m.object)
                    && let Some(prop_name) = extract_string_literal(&m.expression)
                {
                    let raw = format!("process.env[\"{}\"]", prop_name);
                    self.record_access(&prop_name, m.span, AccessKind::ProcessEnv, &raw);
                    return;
                }
                self.walk_expression(&m.object);
                self.walk_expression(&m.expression);
            }

            // Check Call expressions: c.get('MY_VAR') or c.env.get('MY_KV') or env.get('MY_KV')
            Expression::CallExpression(call) => {
                if let Expression::StaticMemberExpression(m) = &call.callee {
                    let method_name = m.property.name.as_str();
                    if method_name == "get" {
                        // Check if object is `c` (Hono context) or `env`
                        if (is_ident_name(&m.object, "c") || is_env_source(&m.object).is_some())
                            && let Some(first_arg) = call.arguments.first()
                            && let Some(arg_expr) = first_arg.as_expression()
                            && let Some(key_name) = extract_string_literal(arg_expr)
                        {
                            let raw = format!("c.get('{}')", key_name);
                            self.record_access(&key_name, call.span, AccessKind::HelperCall, &raw);
                        }
                    }
                }

                self.walk_expression(&call.callee);
                for arg in &call.arguments {
                    if let Some(e) = arg.as_expression() {
                        self.walk_expression(e);
                    }
                }
            }

            // New expression: new Response(env.VAR)
            Expression::NewExpression(n) => {
                self.walk_expression(&n.callee);
                for arg in &n.arguments {
                    if let Some(e) = arg.as_expression() {
                        self.walk_expression(e);
                    }
                }
            }

            // Assignment expression: ({ MY_KV } = env)
            Expression::AssignmentExpression(assign) => {
                if let Some(env_expr_str) = is_env_source(&assign.right)
                    && let AssignmentTarget::ObjectAssignmentTarget(obj) = &assign.left
                {
                    for prop in &obj.properties {
                        if let AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(ident) =
                            prop
                        {
                            let name = ident.binding.name.as_str();
                            let raw = format!("({{ {} }} = {})", name, env_expr_str);
                            self.record_access(name, ident.span, AccessKind::Destructured, &raw);
                        }
                    }
                }
                self.walk_expression(&assign.right);
            }

            // Object literal: { async fetch(req, env, ctx) { ... } }
            Expression::ObjectExpression(obj) => {
                for prop in &obj.properties {
                    match prop {
                        ObjectPropertyKind::ObjectProperty(p) => {
                            let key_name = p.key.name();
                            if let Expression::FunctionExpression(f) = &p.value {
                                self.walk_function(f, key_name.as_deref());
                            } else if let Expression::ArrowFunctionExpression(f) = &p.value {
                                self.walk_arrow_function(f, key_name.as_deref());
                            } else {
                                self.walk_expression(&p.value);
                            }
                        }
                        ObjectPropertyKind::SpreadProperty(s) => {
                            self.walk_expression(&s.argument);
                        }
                    }
                }
            }

            Expression::FunctionExpression(f) => {
                self.walk_function(f, None);
            }
            Expression::ArrowFunctionExpression(f) => {
                self.walk_arrow_function(f, None);
            }
            Expression::ArrayExpression(arr) => {
                for el in &arr.elements {
                    if let Some(e) = el.as_expression() {
                        self.walk_expression(e);
                    }
                }
            }
            Expression::AwaitExpression(a) => {
                self.walk_expression(&a.argument);
            }
            Expression::UnaryExpression(u) => {
                self.walk_expression(&u.argument);
            }
            Expression::UpdateExpression(u) => {
                if let Some(m) = u.argument.as_member_expression() {
                    self.walk_member_expression(m);
                }
            }
            Expression::BinaryExpression(b) => {
                self.walk_expression(&b.left);
                self.walk_expression(&b.right);
            }
            Expression::LogicalExpression(l) => {
                self.walk_expression(&l.left);
                self.walk_expression(&l.right);
            }
            Expression::ConditionalExpression(c) => {
                self.walk_expression(&c.test);
                self.walk_expression(&c.consequent);
                self.walk_expression(&c.alternate);
            }
            Expression::SequenceExpression(s) => {
                for e in &s.expressions {
                    self.walk_expression(e);
                }
            }
            Expression::ParenthesizedExpression(p) => {
                self.walk_expression(&p.expression);
            }
            Expression::ChainExpression(c) => {
                if let Some(m) = c.expression.member_expression() {
                    self.walk_member_expression(m);
                } else if let ChainElement::CallExpression(call) = &c.expression {
                    self.walk_expression(&call.callee);
                    for arg in &call.arguments {
                        if let Some(e) = arg.as_expression() {
                            self.walk_expression(e);
                        }
                    }
                }
            }
            Expression::TSAsExpression(a) => {
                self.walk_expression(&a.expression);
            }
            Expression::TSTypeAssertion(a) => {
                self.walk_expression(&a.expression);
            }
            Expression::TSNonNullExpression(n) => {
                self.walk_expression(&n.expression);
            }
            Expression::TSSatisfiesExpression(s) => {
                self.walk_expression(&s.expression);
            }
            Expression::TemplateLiteral(t) => {
                for e in &t.expressions {
                    self.walk_expression(e);
                }
            }
            Expression::TaggedTemplateExpression(t) => {
                self.walk_expression(&t.tag);
            }
            Expression::YieldExpression(y) => {
                if let Some(arg) = &y.argument {
                    self.walk_expression(arg);
                }
            }
            Expression::ImportExpression(i) => {
                self.walk_expression(&i.source);
            }
            _ => {}
        }
    }

    fn walk_arrow_function(&mut self, func: &ArrowFunctionExpression, func_name: Option<&str>) {
        let is_worker_handler = func_name.is_some_and(|name| {
            matches!(
                name,
                "fetch"
                    | "scheduled"
                    | "queue"
                    | "email"
                    | "tail"
                    | "trace"
                    | "onRequest"
                    | "onRequestGet"
                    | "onRequestPost"
                    | "onRequestPut"
                    | "onRequestDelete"
            )
        });

        for (param_idx, param) in func.params.items.iter().enumerate() {
            if let BindingPattern::ObjectPattern(obj) = &param.pattern {
                for prop in &obj.properties {
                    if let Some(prop_name) = prop.key.name() {
                        if prop_name == "env" {
                            if let BindingPattern::ObjectPattern(nested_obj) = &prop.value {
                                for nested_prop in &nested_obj.properties {
                                    if let Some(nested_name) = nested_prop.key.name() {
                                        let raw = format!("{{ env: {{ {} }} }}", nested_name);
                                        self.record_access(
                                            &nested_name,
                                            nested_prop.span,
                                            AccessKind::ParamDestructured,
                                            &raw,
                                        );
                                    }
                                }
                            }
                        } else if (param_idx == 1
                            && (is_worker_handler || func.params.items.len() >= 2))
                            || (param_idx == 0 && is_worker_handler)
                        {
                            let raw = format!("handler(req, {{ {} }}, ctx)", prop_name);
                            self.record_access(
                                &prop_name,
                                prop.span,
                                AccessKind::ParamDestructured,
                                &raw,
                            );
                        }
                    }
                }
            }
        }

        match &func.body {
            ArrowFunctionBody::FunctionBody(b) => {
                for stmt in &b.statements {
                    self.walk_statement(stmt);
                }
            }
            _ => {
                if let Some(expr) = func.body.as_expression() {
                    self.walk_expression(expr);
                }
            }
        }
    }

    fn walk_member_expression(&mut self, m: &MemberExpression) {
        match m {
            MemberExpression::StaticMemberExpression(s) => {
                if let Some(env_expr_str) = is_env_source(&s.object) {
                    let prop_name = s.property.name.as_str();
                    let raw = format!("{}.{}", env_expr_str, prop_name);
                    self.record_access(prop_name, s.span, AccessKind::DirectMember, &raw);
                } else if is_process_env(&s.object) {
                    let prop_name = s.property.name.as_str();
                    let raw = format!("process.env.{}", prop_name);
                    self.record_access(prop_name, s.span, AccessKind::ProcessEnv, &raw);
                } else {
                    self.walk_expression(&s.object);
                }
            }
            MemberExpression::ComputedMemberExpression(c) => {
                if let Some(env_expr_str) = is_env_source(&c.object) {
                    if let Some(prop_name) = extract_string_literal(&c.expression) {
                        let raw = format!("{}[\"{}\"]", env_expr_str, prop_name);
                        self.record_access(&prop_name, c.span, AccessKind::DirectMember, &raw);
                        return;
                    }
                } else if is_process_env(&c.object)
                    && let Some(prop_name) = extract_string_literal(&c.expression)
                {
                    let raw = format!("process.env[\"{}\"]", prop_name);
                    self.record_access(&prop_name, c.span, AccessKind::ProcessEnv, &raw);
                    return;
                }
                self.walk_expression(&c.object);
                self.walk_expression(&c.expression);
            }
            _ => {}
        }
    }
}

// ==========================================
// Helper functions for matching env sources
// ==========================================

/// Checks if an identifier expression matches a specific name
fn is_ident_name(expr: &Expression, expected: &str) -> bool {
    if let Expression::Identifier(ident) = expr {
        ident.name == expected
    } else {
        false
    }
}

/// Checks if an expression is `process.env`
fn is_process_env(expr: &Expression) -> bool {
    let chain = get_member_chain(expr);
    chain == "process.env"
}

/// Determines if an expression is an environment access root (e.g. `env`, `c.env`, `context.env`, `Astro.locals.runtime.env`).
/// Returns a friendly string description of the environment source (e.g. `"c.env"`).
fn is_env_source(expr: &Expression) -> Option<String> {
    let chain = get_member_chain(expr);
    match chain.as_str() {
        "env"
        | "c.env"
        | "context.env"
        | "ctx.env"
        | "request.env"
        | "event.env"
        | "this.env"
        | "props.env"
        | "locals.env"
        | "Astro.locals.env"
        | "Astro.locals.runtime.env" => Some(chain),
        _ if chain.ends_with(".env") => Some(chain),
        _ => None,
    }
}

/// Extracts full member chain like "Astro.locals.runtime.env"
fn get_member_chain(expr: &Expression) -> String {
    match expr {
        Expression::Identifier(id) => id.name.to_string(),
        Expression::ThisExpression(_) => "this".to_string(),
        Expression::StaticMemberExpression(m) => {
            let parent = get_member_chain(&m.object);
            if parent.is_empty() {
                m.property.name.to_string()
            } else {
                format!("{}.{}", parent, m.property.name)
            }
        }
        _ => String::new(),
    }
}

/// Extracts string literal value from expression if present
fn extract_string_literal(expr: &Expression) -> Option<String> {
    match expr {
        Expression::StringLiteral(s) => Some(s.value.to_string()),
        Expression::TemplateLiteral(t) if t.expressions.is_empty() && !t.quasis.is_empty() => t
            .quasis
            .first()
            .and_then(|q| q.value.cooked.as_ref())
            .map(|c| c.to_string()),
        _ => None,
    }
}

/// Parse and scan a source file (supporting TS, JS, TSX, JSX, and Astro).
pub fn scan_source_file(
    path: &Path,
) -> Result<Vec<BindingAccess>, Box<dyn std::error::Error + Send + Sync>> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read source file {}: {}", path.display(), e))?;
    let path_str = path.to_string_lossy().to_string();

    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if ext == "astro" {
        scan_astro_content(&path_str, &content)
    } else {
        let source_type = match ext {
            "ts" => SourceType::ts(),
            "tsx" => SourceType::tsx(),
            "jsx" => SourceType::jsx(),
            _ => SourceType::mjs(),
        };
        scan_code_content(&path_str, &content, source_type)
    }
}

/// Scan arbitrary source code content with specified SourceType
pub fn scan_code_content(
    file_path: &str,
    source_text: &str,
    source_type: SourceType,
) -> Result<Vec<BindingAccess>, Box<dyn std::error::Error + Send + Sync>> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source_text, source_type).parse();

    let mut scanner = AstScanner::new(file_path, source_text);
    let accesses = scanner.scan_program(&parsed.program);
    Ok(accesses)
}

/// Scan `.astro` file content by extracting frontmatter and script blocks while preserving line numbering.
pub fn scan_astro_content(
    file_path: &str,
    source_text: &str,
) -> Result<Vec<BindingAccess>, Box<dyn std::error::Error + Send + Sync>> {
    let mut all_accesses = Vec::new();

    // 1. Extract Frontmatter (between first --- and second ---)
    let lines: Vec<&str> = source_text.lines().collect();
    if let Some(first_fence) = lines.iter().position(|l| l.trim() == "---")
        && let Some(second_fence_offset) = lines[first_fence + 1..]
            .iter()
            .position(|l| l.trim() == "---")
    {
        let second_fence = first_fence + 1 + second_fence_offset;

        // Build padded source so line numbers match the .astro file exactly
        let mut padded_script = String::new();
        for _ in 0..first_fence + 1 {
            padded_script.push('\n');
        }
        for line in lines.iter().take(second_fence).skip(first_fence + 1) {
            padded_script.push_str(line);
            padded_script.push('\n');
        }

        let fm_accesses = scan_code_content(file_path, &padded_script, SourceType::ts())?;
        all_accesses.extend(fm_accesses);
    }

    // 2. Extract <script> tags
    let mut script_start = 0;
    while let Some(start_tag) = source_text[script_start..].find("<script") {
        let tag_abs_start = script_start + start_tag;
        if let Some(tag_close) = source_text[tag_abs_start..].find('>') {
            let content_start = tag_abs_start + tag_close + 1;
            if let Some(end_tag) = source_text[content_start..].find("</script>") {
                let content_end = content_start + end_tag;
                let script_body = &source_text[content_start..content_end];

                // Calculate number of preceding lines to pad
                let preceding_text = &source_text[..content_start];
                let line_count = preceding_text.matches('\n').count();

                let mut padded_script = String::new();
                for _ in 0..line_count {
                    padded_script.push('\n');
                }
                padded_script.push_str(script_body);

                if let Ok(script_accesses) =
                    scan_code_content(file_path, &padded_script, SourceType::ts())
                {
                    all_accesses.extend(script_accesses);
                }

                script_start = content_end + 9;
                continue;
            }
        }
        break;
    }

    Ok(all_accesses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_all_patterns() {
        let code = r#"
        import { Hono } from 'hono';

        const app = new Hono();

        // 1. Direct env access
        const kv = env.MY_KV;
        const db = c.env.MY_D1;
        const bucket = context.env.MY_R2;
        const ai = Astro.locals.runtime.env.AI_MODEL;
        const localAi = locals.env.LOCAL_AI;

        // 2. Computed member access
        const computedKv = env['COMPUTED_KV'];
        const bracketD1 = c.env["BRACKET_D1"];

        // 3. Destructuring
        const { VAR_A, VAR_B: aliasB } = env;
        const { HONO_SECRET } = c.env;
        const { ASTRO_VAR } = Astro.locals.runtime.env;

        // 4. Process.env
        const apiKey = process.env.API_KEY;
        const { PROCESS_VAR } = process.env;

        // 5. Helper call
        const helperVar = c.get('HONO_VAR');

        // 6. Function parameter destructuring
        export default {
            async fetch(request, { HANDLER_KV, HANDLER_DB }, ctx) {
                return new Response("ok");
            },
            async scheduled(event, { CRON_SECRET }, ctx) {
                // cron
            }
        };

        // 7. Pages function handler
        export const onRequest = async ({ env: { PAGES_KV } }) => {
            return new Response("ok");
        };
        "#;

        let accesses = scan_code_content("test.ts", code, SourceType::ts()).unwrap();
        let names: Vec<&str> = accesses.iter().map(|a| a.name.as_str()).collect();

        assert!(names.contains(&"MY_KV"));
        assert!(names.contains(&"MY_D1"));
        assert!(names.contains(&"MY_R2"));
        assert!(names.contains(&"AI_MODEL"));
        assert!(names.contains(&"LOCAL_AI"));
        assert!(names.contains(&"COMPUTED_KV"));
        assert!(names.contains(&"BRACKET_D1"));
        assert!(names.contains(&"VAR_A"));
        assert!(names.contains(&"VAR_B"));
        assert!(names.contains(&"HONO_SECRET"));
        assert!(names.contains(&"ASTRO_VAR"));
        assert!(names.contains(&"API_KEY"));
        assert!(names.contains(&"PROCESS_VAR"));
        assert!(names.contains(&"HONO_VAR"));
        assert!(names.contains(&"HANDLER_KV"));
        assert!(names.contains(&"HANDLER_DB"));
        assert!(names.contains(&"CRON_SECRET"));
        assert!(names.contains(&"PAGES_KV"));
    }

    #[test]
    fn test_scan_astro_frontmatter() {
        let astro_code = r#"---
import Header from '../components/Header.astro';
const db = Astro.locals.runtime.env.ASTRO_DB;
const { ASTRO_KV } = Astro.locals.env;
---

<div>
  <h1>Hello</h1>
</div>

<script>
  console.log("Client script");
</script>
"#;
        let accesses = scan_astro_content("src/pages/index.astro", astro_code).unwrap();
        let names: Vec<&str> = accesses.iter().map(|a| a.name.as_str()).collect();
        assert!(names.contains(&"ASTRO_DB"));
        assert!(names.contains(&"ASTRO_KV"));

        // Check line numbers match frontmatter lines (line 3 and 4)
        let db_access = accesses.iter().find(|a| a.name == "ASTRO_DB").unwrap();
        assert_eq!(db_access.line, 3);
        let kv_access = accesses.iter().find(|a| a.name == "ASTRO_KV").unwrap();
        assert_eq!(kv_access.line, 4);
    }
}
