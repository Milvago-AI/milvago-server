use crate::model::*;

#[derive(Clone)]
struct Token { text: String, string: bool, at: usize }

struct Parser<'a> { source: &'a str, tokens: Vec<Token>, at: usize, nodes: usize }

impl Parser<'_> {
    fn error(&self, message: &str) -> String {
        let at = self.tokens.get(self.at).map_or(self.source.len(), |t| t.at);
        let prefix = &self.source[..at];
        format!("{}:{}: {}", prefix.bytes().filter(|b| *b == b'\n').count() + 1, prefix.rsplit('\n').next().unwrap_or("").chars().count() + 1, message)
    }
    fn take(&mut self, value: &str) -> bool {
        if self.tokens.get(self.at).is_some_and(|t| !t.string && t.text.eq_ignore_ascii_case(value)) { self.at += 1; true } else { false }
    }
    fn expect(&mut self, value: &str) -> Result<(), String> {
        if self.take(value) { Ok(()) } else { Err(self.error(&format!("Expected {value}"))) }
    }
    fn string(&mut self) -> Result<String, String> {
        let token = self.tokens.get(self.at).filter(|t| t.string).ok_or_else(|| self.error("Expected a quoted string"))?;
        let result = token.text.clone(); self.at += 1; Ok(result)
    }
    fn name(&mut self) -> Result<String, String> {
        let token = self.tokens.get(self.at).filter(|t| !t.string && t.text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')).ok_or_else(|| self.error("Expected a field name"))?;
        let result = token.text.to_ascii_lowercase(); self.at += 1; Ok(result)
    }
    fn detector(&mut self) -> Result<String, String> {
        self.expect("detector")?; self.expect("(")?; let name = self.string()?; self.expect(")")?; Ok(name)
    }
    fn expr(&mut self, depth: usize) -> Result<Expr, String> {
        if depth > MAX_DEPTH { return Err(self.error("Condition nesting exceeds the limit")); }
        let first = self.atom(depth + 1)?;
        let mut children = vec![first];
        let mut operator = String::new();
        while let Some(next) = self.tokens.get(self.at).filter(|t| !t.string && ["AND", "OR", "XOR"].iter().any(|v| t.text.eq_ignore_ascii_case(v))) {
            let next = next.text.to_ascii_uppercase();
            if !operator.is_empty() && operator != next { return Err(self.error("Use parentheses when mixing AND, OR and XOR")); }
            operator = next; self.at += 1; children.push(self.atom(depth + 1)?);
        }
        Ok(match operator.as_str() {
            "AND" => Expr::All { children }, "OR" => Expr::Any { children }, "XOR" => Expr::One { children }, _ => children.remove(0),
        })
    }
    fn atom(&mut self, depth: usize) -> Result<Expr, String> {
        self.nodes += 1;
        if depth > MAX_DEPTH || self.nodes > MAX_NODES { return Err(self.error("Condition complexity exceeds the limit")); }
        if self.take("NOT") { return Ok(Expr::Not { child: Box::new(self.atom(depth + 1)?) }); }
        if self.take("(") { let e = self.expr(depth + 1)?; self.expect(")")?; return Ok(e); }
        if self.take("TRUE") { return Ok(Expr::True); }
        if self.take("UPLOAD") { return Ok(Expr::Upload); }
        let field = self.name()?;
        if self.take("CONTAINS") {
            let value = self.string()?; let ignore_case = self.take("IGNORECASE"); let whole_word = self.take("WORD");
            return Ok(Expr::Contains { field, value, ignore_case, whole_word });
        }
        if self.take("MATCHES") {
            let detector = self.detector()?;
            let minimum = if self.take("ATLEAST") { self.name()?.parse::<usize>().map_err(|_| self.error("Expected a bounded occurrence count"))? } else { 1 };
            return Ok(Expr::Matches { field, detector, minimum });
        }
        if self.take("IN") {
            self.expect("[")?; let mut values = vec![self.string()?];
            while self.take(",") { values.push(self.string()?); if values.len() > 128 { return Err(self.error("Too many scope values")); } }
            self.expect("]")?; return Ok(Expr::In { field, values });
        }
        self.expect("=")?; let value = self.string()?;
        Ok(Expr::Eq { field, value })
    }
}

fn tokenize(source: &str) -> Result<Vec<Token>, String> {
    if source.len() > 16384 { return Err("1:1: Rule source exceeds the limit".into()); }
    let mut result = Vec::new(); let mut at = 0;
    while at < source.len() {
        let c = source[at..].chars().next().ok_or("Invalid source")?;
        if c.is_whitespace() { at += c.len_utf8(); continue; }
        let start = at;
        if c == '"' {
            at += 1; let mut escape = false; let mut closed = false;
            while at < source.len() {
                let c = source.as_bytes()[at]; at += 1;
                if escape { escape = false; } else if c == b'\\' { escape = true; } else if c == b'"' { closed = true; break; }
            }
            if !closed { return Err("1:1: Unterminated quoted string".into()); }
            let text: String = serde_json::from_str(&source[start..at]).map_err(|_| "1:1: Invalid quoted string")?;
            if text.len() > 1024 { return Err("1:1: String exceeds the limit".into()); }
            result.push(Token { text, string: true, at: start });
        } else if "()[]=,".contains(c) {
            at += c.len_utf8(); result.push(Token { text: c.to_string(), string: false, at: start });
        } else if c.is_ascii_alphanumeric() || c == '_' {
            at += 1;
            while at < source.len() && (source.as_bytes()[at].is_ascii_alphanumeric() || source.as_bytes()[at] == b'_') { at += 1; }
            result.push(Token { text: source[start..at].into(), string: false, at: start });
        } else { return Err("1:1: Unsupported character outside a quoted string".into()); }
        if result.len() > 2048 { return Err("1:1: Rule source is too complex".into()); }
    }
    Ok(result)
}

pub fn parse(source: &str) -> Result<Rule, String> {
    let mut p = Parser { source, tokens: tokenize(source)?, at: 0, nodes: 0 };
    p.expect("WHEN")?; let condition = p.expr(0)?;
    p.expect("SCOPE")?; let scope = p.expr(0)?;
    p.expect("THEN")?;
    let consequence = if p.take("OBSERVE") { Effect::Observe }
        else if p.take("WARN") { Effect::Warn }
        else if p.take("BLOCK") { Effect::Block }
        else if p.take("MASK") { let detector = p.detector()?; p.expect("AS")?; Effect::Mask { detector, label: p.string()? } }
        else if p.take("REPLACE") { let value = p.string()?; p.expect("WITH")?; let replacement = p.string()?; let ignore_case = p.take("IGNORECASE"); let whole_word = p.take("WORD"); Effect::Replace { value, replacement, ignore_case, whole_word } }
        else { return Err(p.error("Expected OBSERVE, WARN, BLOCK, MASK or REPLACE")); };
    let review = p.take("REVIEW");
    let message = if p.take("MESSAGE") { p.string()? } else { String::new() };
    if p.at != p.tokens.len() { return Err(p.error("Unexpected text after the consequence")); }
    Ok(Rule { application: None, id: "draft".into(), revision: 1, name: "Draft".into(), mode: Mode::Simulation, priority: 100, condition, scope, consequence, review, message })
}

fn quote(value: &str) -> String { serde_json::to_string(value).unwrap_or_else(|_| "\"\"".into()) }
fn expression(value: &Expr) -> String {
    match value {
        Expr::True => "TRUE".into(), Expr::Upload => "UPLOAD".into(),
        Expr::Not { child } => format!("NOT ({})", expression(child)),
        Expr::All { children } | Expr::Any { children } | Expr::One { children } => {
            let op = match value { Expr::All { .. } => " AND ", Expr::Any { .. } => " OR ", _ => " XOR " };
            format!("({})", children.iter().map(expression).collect::<Vec<_>>().join(op))
        }
        Expr::Contains { field, value, ignore_case, whole_word } => format!("{field} CONTAINS {}{}{}", quote(value), if *ignore_case { " IGNORECASE" } else { "" }, if *whole_word { " WORD" } else { "" }),
        Expr::Matches { field, detector, minimum } => format!("{field} MATCHES detector({}){}", quote(detector), if *minimum == 1 { String::new() } else { format!(" ATLEAST {minimum}") }),
        Expr::Eq { field, value } => format!("{field} = {}", quote(value)),
        Expr::In { field, values } => format!("{field} IN [{}]", values.iter().map(|v| quote(v)).collect::<Vec<_>>().join(", ")),
    }
}
pub fn print(rule: &Rule) -> String {
    let effect = match &rule.consequence {
        Effect::Observe => "OBSERVE".into(), Effect::Warn => "WARN".into(), Effect::Block => "BLOCK".into(),
        Effect::Mask { detector, label } => format!("MASK detector({}) AS {}", quote(detector), quote(label)),
        Effect::Replace { value, replacement, ignore_case, whole_word } => format!("REPLACE {} WITH {}{}{}", quote(value), quote(replacement), if *ignore_case { " IGNORECASE" } else { "" }, if *whole_word { " WORD" } else { "" }),
    };
    format!("WHEN {}\nSCOPE {}\nTHEN {}{}{}", expression(&rule.condition), expression(&rule.scope), effect, if rule.review { " REVIEW" } else { "" }, if rule.message.is_empty() { String::new() } else { format!(" MESSAGE {}", quote(&rule.message)) })
}
