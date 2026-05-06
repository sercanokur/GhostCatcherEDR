package rules

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Expr is a compiled rule expression. It evaluates to a boolean against an
// EventFacts snapshot. The engine is deliberately small: boolean AND/OR/NOT,
// comparison operators, a handful of domain-specific identifiers, and a few
// functions (signal, matches, in). This keeps the agent self-contained,
// avoids a heavy CEL dependency, and still covers every pattern the plan
// calls for.
//
// Supported grammar (left to right, precedence as shown):
//
//   primary    := literal | ident | "(" expr ")"
//   literal    := number | string | list
//   string     := '"' (\\" | [^"])* '"'
//   list       := "[" expr ("," expr)* "]"
//   call       := ident "(" [expr ("," expr)*] ")"
//   unary      := ["not"] primary
//   cmp        := unary (("==" | "!=" | "<=" | ">=" | "<" | ">" | "contains" | "matches" | "in") unary)?
//   conj       := cmp ("and" cmp)*
//   disj       := conj ("or" conj)*
//   expr       := disj
//
// Supported identifiers (facts):
//   rule_id, tactic, confidence, entity_path, entity_id, comm, uid, euid,
//   signals (list of strings), techniques (list of strings), container_runtime.
//
// Supported functions:
//   signal("X")   ~ "X" in signals
//   matches("re") ~ applied to left-hand side as regex
//
// Any parse/eval error is surfaced to the caller; a false eval on an
// unknown identifier is treated as an error to keep misspelled rules
// loud rather than silently never-firing.
type Expr struct {
	node node
	src  string
}

// EventFacts is the fact bag provided to each Expr.Eval call. Detectors
// populate this structure at emit-time; missing fields are treated as zero
// values which only matter for explicit comparisons.
type EventFacts struct {
	RuleID           string
	Tactic           string
	Confidence       int
	EntityPath       string
	EntityID         string
	Comm             string
	UID              int
	EUID             int
	ContainerRuntime string
	Signals          []string
	Techniques       []string
}

// CompileExpr parses and returns a reusable expression. Empty input returns
// a "true" expression (useful as the default when a rule has no filter).
func CompileExpr(src string) (*Expr, error) {
	src = strings.TrimSpace(src)
	if src == "" {
		return &Expr{node: literalNode{b: true, hasBool: true}, src: ""}, nil
	}
	p := newParser(src)
	n, err := p.parseDisj()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokEOF {
		return nil, fmt.Errorf("unexpected trailing %q", p.tokens[p.pos].val)
	}
	return &Expr{node: n, src: src}, nil
}

// Eval returns true iff the expression fires against facts.
func (e *Expr) Eval(facts EventFacts) (bool, error) {
	v, err := e.node.eval(facts)
	if err != nil {
		return false, err
	}
	b, ok := toBool(v)
	if !ok {
		return false, fmt.Errorf("expression did not yield boolean")
	}
	return b, nil
}

// Source returns the original text of the expression for logs/evidence.
func (e *Expr) Source() string { return e.src }

// --------- internal AST + evaluator ---------

type node interface {
	eval(f EventFacts) (any, error)
}

type literalNode struct {
	s       string
	n       int
	b       bool
	list    []any
	hasStr  bool
	hasInt  bool
	hasBool bool
	hasList bool
}

func (l literalNode) eval(_ EventFacts) (any, error) {
	switch {
	case l.hasStr:
		return l.s, nil
	case l.hasInt:
		return l.n, nil
	case l.hasBool:
		return l.b, nil
	case l.hasList:
		return l.list, nil
	}
	return nil, fmt.Errorf("empty literal")
}

type identNode struct{ name string }

func (i identNode) eval(f EventFacts) (any, error) {
	switch i.name {
	case "rule_id":
		return f.RuleID, nil
	case "tactic":
		return f.Tactic, nil
	case "confidence":
		return f.Confidence, nil
	case "entity_path":
		return f.EntityPath, nil
	case "entity_id":
		return f.EntityID, nil
	case "comm":
		return f.Comm, nil
	case "uid":
		return f.UID, nil
	case "euid":
		return f.EUID, nil
	case "container_runtime":
		return f.ContainerRuntime, nil
	case "signals":
		out := make([]any, 0, len(f.Signals))
		for _, s := range f.Signals {
			out = append(out, s)
		}
		return out, nil
	case "techniques":
		out := make([]any, 0, len(f.Techniques))
		for _, s := range f.Techniques {
			out = append(out, s)
		}
		return out, nil
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return nil, fmt.Errorf("unknown identifier %q", i.name)
}

type binOpNode struct {
	op       string
	a, b     node
}

func (bn binOpNode) eval(f EventFacts) (any, error) {
	left, err := bn.a.eval(f)
	if err != nil {
		return nil, err
	}
	switch bn.op {
	case "and":
		lb, ok := toBool(left)
		if !ok {
			return nil, fmt.Errorf("'and' lhs not bool")
		}
		if !lb {
			return false, nil
		}
		right, err := bn.b.eval(f)
		if err != nil {
			return nil, err
		}
		rb, ok := toBool(right)
		if !ok {
			return nil, fmt.Errorf("'and' rhs not bool")
		}
		return lb && rb, nil
	case "or":
		lb, ok := toBool(left)
		if !ok {
			return nil, fmt.Errorf("'or' lhs not bool")
		}
		if lb {
			return true, nil
		}
		right, err := bn.b.eval(f)
		if err != nil {
			return nil, err
		}
		rb, ok := toBool(right)
		if !ok {
			return nil, fmt.Errorf("'or' rhs not bool")
		}
		return lb || rb, nil
	}
	right, err := bn.b.eval(f)
	if err != nil {
		return nil, err
	}
	return cmpEval(bn.op, left, right)
}

type notNode struct{ n node }

func (u notNode) eval(f EventFacts) (any, error) {
	v, err := u.n.eval(f)
	if err != nil {
		return nil, err
	}
	b, ok := toBool(v)
	if !ok {
		return nil, fmt.Errorf("'not' requires boolean operand")
	}
	return !b, nil
}

type callNode struct {
	name string
	args []node
}

func (c callNode) eval(f EventFacts) (any, error) {
	switch c.name {
	case "signal":
		if len(c.args) != 1 {
			return nil, fmt.Errorf("signal() takes 1 arg")
		}
		v, err := c.args[0].eval(f)
		if err != nil {
			return nil, err
		}
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("signal() arg must be string")
		}
		for _, have := range f.Signals {
			if have == s || strings.HasPrefix(have, s+":") {
				return true, nil
			}
		}
		return false, nil
	case "matches":
		if len(c.args) != 2 {
			return nil, fmt.Errorf("matches(subject, pattern) needs 2 args")
		}
		subjV, err := c.args[0].eval(f)
		if err != nil {
			return nil, err
		}
		patV, err := c.args[1].eval(f)
		if err != nil {
			return nil, err
		}
		s, ok := subjV.(string)
		if !ok {
			return nil, fmt.Errorf("matches() subject must be string")
		}
		p, ok := patV.(string)
		if !ok {
			return nil, fmt.Errorf("matches() pattern must be string")
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		return re.MatchString(s), nil
	case "technique":
		if len(c.args) != 1 {
			return nil, fmt.Errorf("technique() takes 1 arg")
		}
		v, err := c.args[0].eval(f)
		if err != nil {
			return nil, err
		}
		t, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("technique() arg must be string")
		}
		for _, have := range f.Techniques {
			if have == t {
				return true, nil
			}
		}
		return false, nil
	}
	return nil, fmt.Errorf("unknown function %q", c.name)
}

func cmpEval(op string, a, b any) (bool, error) {
	switch op {
	case "==":
		return equalAny(a, b), nil
	case "!=":
		return !equalAny(a, b), nil
	case "<", "<=", ">", ">=":
		ai, aok := toInt(a)
		bi, bok := toInt(b)
		if !aok || !bok {
			return false, fmt.Errorf("numeric cmp requires ints")
		}
		switch op {
		case "<":
			return ai < bi, nil
		case "<=":
			return ai <= bi, nil
		case ">":
			return ai > bi, nil
		case ">=":
			return ai >= bi, nil
		}
	case "contains":
		as, aok := a.(string)
		bs, bok := b.(string)
		if aok && bok {
			return strings.Contains(as, bs), nil
		}
		if lst, ok := a.([]any); ok {
			for _, item := range lst {
				if equalAny(item, b) {
					return true, nil
				}
			}
			return false, nil
		}
		return false, fmt.Errorf("'contains' needs (string,string) or (list, item)")
	case "matches":
		as, aok := a.(string)
		bs, bok := b.(string)
		if !aok || !bok {
			return false, fmt.Errorf("'matches' needs (string, regex)")
		}
		re, err := regexp.Compile(bs)
		if err != nil {
			return false, err
		}
		return re.MatchString(as), nil
	case "in":
		lst, ok := b.([]any)
		if !ok {
			return false, fmt.Errorf("'in' rhs must be list")
		}
		for _, item := range lst {
			if equalAny(item, a) {
				return true, nil
			}
		}
		return false, nil
	}
	return false, fmt.Errorf("unknown op %q", op)
}

func toBool(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	}
	return false, false
}

func toInt(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		return int(x), true
	}
	return 0, false
}

func equalAny(a, b any) bool {
	switch av := a.(type) {
	case string:
		if bv, ok := b.(string); ok {
			return av == bv
		}
	case int:
		if bv, ok := b.(int); ok {
			return av == bv
		}
	case bool:
		if bv, ok := b.(bool); ok {
			return av == bv
		}
	}
	return false
}

// --------- lexer / parser ---------

type tokKind int

const (
	tokEOF tokKind = iota
	tokIdent
	tokNum
	tokStr
	tokLP
	tokRP
	tokLB
	tokRB
	tokComma
	tokOp
)

type token struct {
	kind tokKind
	val  string
}

type parser struct {
	src    string
	pos    int
	tokens []token
}

func newParser(src string) *parser {
	p := &parser{src: src}
	p.tokens = p.tokenize()
	return p
}

// opSet contains symbols that are always operators. Function-only keywords
// like `matches` are not listed here; they are parsed as identifiers and
// disambiguated by the following '('.
var opSet = map[string]struct{}{
	"==": {}, "!=": {}, "<=": {}, ">=": {}, "<": {}, ">": {},
	"contains": {}, "in": {},
	"and": {}, "or": {}, "not": {},
}

func (p *parser) tokenize() []token {
	var out []token
	s := p.src
	for i := 0; i < len(s); {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' {
			i++
			continue
		}
		if c == '(' {
			out = append(out, token{tokLP, "("})
			i++
			continue
		}
		if c == ')' {
			out = append(out, token{tokRP, ")"})
			i++
			continue
		}
		if c == '[' {
			out = append(out, token{tokLB, "["})
			i++
			continue
		}
		if c == ']' {
			out = append(out, token{tokRB, "]"})
			i++
			continue
		}
		if c == ',' {
			out = append(out, token{tokComma, ","})
			i++
			continue
		}
		if c == '"' {
			j := i + 1
			var buf strings.Builder
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' && j+1 < len(s) {
					buf.WriteByte(s[j+1])
					j += 2
					continue
				}
				buf.WriteByte(s[j])
				j++
			}
			out = append(out, token{tokStr, buf.String()})
			i = j + 1
			continue
		}
		if c >= '0' && c <= '9' {
			j := i
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			out = append(out, token{tokNum, s[i:j]})
			i = j
			continue
		}
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' {
			j := i
			for j < len(s) && ((s[j] >= 'a' && s[j] <= 'z') || (s[j] >= 'A' && s[j] <= 'Z') || (s[j] >= '0' && s[j] <= '9') || s[j] == '_') {
				j++
			}
			word := s[i:j]
			if _, ok := opSet[word]; ok {
				out = append(out, token{tokOp, word})
			} else {
				out = append(out, token{tokIdent, word})
			}
			i = j
			continue
		}
		// Two-char operators first.
		if i+1 < len(s) {
			two := s[i : i+2]
			if _, ok := opSet[two]; ok {
				out = append(out, token{tokOp, two})
				i += 2
				continue
			}
		}
		// Single-char operators.
		if c == '<' || c == '>' {
			out = append(out, token{tokOp, string(c)})
			i++
			continue
		}
		// Unknown char - skip (lenient).
		i++
	}
	out = append(out, token{tokEOF, ""})
	return out
}

func (p *parser) peek() token {
	if p.pos >= len(p.tokens) {
		return token{tokEOF, ""}
	}
	return p.tokens[p.pos]
}

func (p *parser) next() token {
	t := p.peek()
	p.pos++
	return t
}

func (p *parser) expect(k tokKind) (token, error) {
	t := p.next()
	if t.kind != k {
		return t, fmt.Errorf("expected tok %d, got %q", k, t.val)
	}
	return t, nil
}

func (p *parser) parseDisj() (node, error) {
	n, err := p.parseConj()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t.kind == tokOp && t.val == "or" {
			p.pos++
			r, err := p.parseConj()
			if err != nil {
				return nil, err
			}
			n = binOpNode{op: "or", a: n, b: r}
			continue
		}
		break
	}
	return n, nil
}

func (p *parser) parseConj() (node, error) {
	n, err := p.parseCmp()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t.kind == tokOp && t.val == "and" {
			p.pos++
			r, err := p.parseCmp()
			if err != nil {
				return nil, err
			}
			n = binOpNode{op: "and", a: n, b: r}
			continue
		}
		break
	}
	return n, nil
}

func (p *parser) parseCmp() (node, error) {
	n, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	t := p.peek()
	if t.kind == tokOp {
		switch t.val {
		case "==", "!=", "<=", ">=", "<", ">", "contains", "in":
			p.pos++
			r, err := p.parseUnary()
			if err != nil {
				return nil, err
			}
			return binOpNode{op: t.val, a: n, b: r}, nil
		}
	}
	return n, nil
}

func (p *parser) parseUnary() (node, error) {
	t := p.peek()
	if t.kind == tokOp && t.val == "not" {
		p.pos++
		sub, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		return notNode{n: sub}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (node, error) {
	t := p.next()
	switch t.kind {
	case tokStr:
		return literalNode{s: t.val, hasStr: true}, nil
	case tokNum:
		v, err := strconv.Atoi(t.val)
		if err != nil {
			return nil, err
		}
		return literalNode{n: v, hasInt: true}, nil
	case tokLP:
		n, err := p.parseDisj()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tokRP); err != nil {
			return nil, err
		}
		return n, nil
	case tokLB:
		list, err := p.parseList()
		if err != nil {
			return nil, err
		}
		return literalNode{list: list, hasList: true}, nil
	case tokIdent:
		// Function call?
		if p.peek().kind == tokLP {
			p.pos++ // consume (
			var args []node
			if p.peek().kind != tokRP {
				for {
					a, err := p.parseDisj()
					if err != nil {
						return nil, err
					}
					args = append(args, a)
					if p.peek().kind == tokComma {
						p.pos++
						continue
					}
					break
				}
			}
			if _, err := p.expect(tokRP); err != nil {
				return nil, err
			}
			return callNode{name: t.val, args: args}, nil
		}
		return identNode{name: t.val}, nil
	}
	return nil, fmt.Errorf("unexpected token %q", t.val)
}

func (p *parser) parseList() ([]any, error) {
	var out []any
	if p.peek().kind == tokRB {
		p.pos++
		return out, nil
	}
	for {
		t := p.next()
		switch t.kind {
		case tokStr:
			out = append(out, t.val)
		case tokNum:
			v, err := strconv.Atoi(t.val)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		default:
			return nil, fmt.Errorf("list element expected string or number, got %q", t.val)
		}
		if p.peek().kind == tokComma {
			p.pos++
			continue
		}
		break
	}
	if _, err := p.expect(tokRB); err != nil {
		return nil, err
	}
	return out, nil
}
