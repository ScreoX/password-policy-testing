package passwordpolicy

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// PasswordPolicy проверяет пароль по набору правил и возвращает список нарушений.
//
// Проверки независимы: в результат попадают все нарушения, а не только первое.
// Порядок нарушений в списке не определён, поэтому опираться на него нельзя.
//
// Правила проверки:
//   - пароль равен nil: возвращается ErrNilPassword;
//   - длина меньше MinLength: TooShort;
//   - длина больше MaxLength: TooLong, длина ровно MaxLength допустима;
//   - нет ни одной цифры: NoDigit;
//   - нет ни одной заглавной латинской буквы: NoUpper;
//   - нет ни одной строчной латинской буквы: NoLower;
//   - нет ни одного символа из Special: NoSpecial;
//   - есть пробельный символ: HasWhitespace;
//   - три и более одинаковых символа подряд: RepeatedRun;
//   - пароль содержит непустой логин без учёта регистра: ContainsLogin;
//   - пароль совпадает с password, qwerty, 123456, admin или welcome без учёта регистра: Blacklisted.
//
// Пароль считается валидным, когда список нарушений пуст.
// Реализация учебная и может расходиться со спецификацией. Задача домашней работы:
// найти эти расхождения тестами, написанными по спецификации.
type PasswordPolicy struct{}

// MinLength: минимальная длина пароля.
const MinLength = 8

// MaxLength: максимальная допустимая длина пароля.
const MaxLength = 64

// Special: символы, которые считаются специальными.
const Special = "!@#$%^&*()-_=+"

// ErrNilPassword возвращается, если пароль равен nil.
var ErrNilPassword = errors.New("Пароль не может быть nil")

var blacklist = map[string]struct{}{
	"password": {},
	"qwerty":   {},
	"123456":   {},
	"admin":    {},
	"welcome":  {},
}

// Violation описывает вид нарушения политики.
type Violation string

const (
	TooShort      Violation = "TOO_SHORT"
	TooLong       Violation = "TOO_LONG"
	NoDigit       Violation = "NO_DIGIT"
	NoUpper       Violation = "NO_UPPER"
	NoLower       Violation = "NO_LOWER"
	NoSpecial     Violation = "NO_SPECIAL"
	HasWhitespace Violation = "HAS_WHITESPACE"
	RepeatedRun   Violation = "REPEATED_RUN"
	ContainsLogin Violation = "CONTAINS_LOGIN"
	Blacklisted   Violation = "BLACKLISTED"
)

// Result содержит результат проверки: валиден ли пароль и что именно нарушено.
type Result struct {
	violations []Violation
}

// IsValid возвращает true, если нарушений нет.
func (r Result) IsValid() bool {
	return len(r.violations) == 0
}

// Violations возвращает все найденные нарушения. Порядок не определён.
func (r Result) Violations() []Violation {
	return append([]Violation(nil), r.violations...)
}

// String возвращает строковое представление результата.
func (r Result) String() string {
	if r.IsValid() {
		return "Result{valid}"
	}
	return fmt.Sprintf("Result%v", r.violations)
}

// Check проверяет пароль без учёта логина.
func (p PasswordPolicy) Check(password *string) (Result, error) {
	return p.CheckWithLogin(password, nil)
}

// CheckWithLogin проверяет пароль с учётом логина пользователя.
// Если логин равен nil или пустой строке, правило ContainsLogin не применяется.
// Если пароль равен nil, метод возвращает ErrNilPassword.
func (PasswordPolicy) CheckWithLogin(password *string, login *string) (Result, error) {
	if password == nil {
		return Result{}, ErrNilPassword
	}

	value := *password
	found := make([]Violation, 0)

	length := utf8.RuneCountInString(value)
	if length < MinLength {
		found = append(found, TooShort)
	}
	if length > MaxLength-1 {
		found = append(found, TooLong)
	}

	var digit, upper, lower, special, whitespace bool
	for _, current := range value {
		switch {
		case unicode.IsDigit(current):
			digit = true
		case current >= 'A' && current <= 'Z':
			upper = true
		case current >= 'a' && current <= 'z':
			lower = true
		}

		if strings.ContainsRune(Special, current) {
			special = true
		}
		if unicode.IsSpace(current) {
			whitespace = true
		}
	}

	if !digit {
		found = append(found, NoDigit)
	}
	if !upper {
		found = append(found, NoUpper)
	}
	if !lower {
		found = append(found, NoLower)
	}
	if !special {
		found = append(found, NoSpecial)
	}
	if whitespace {
		found = append(found, HasWhitespace)
	}
	if hasRepeatedRun(value) {
		found = append(found, RepeatedRun)
	}
	if login != nil && *login != "" && strings.Contains(strings.ToLower(value), strings.ToLower(*login)) {
		found = append(found, ContainsLogin)
	}
	if _, exists := blacklist[value]; exists {
		found = append(found, Blacklisted)
	}

	return Result{violations: found}, nil
}

// hasRepeatedRun проверяет, есть ли в строке серия одинаковых символов подряд.
func hasRepeatedRun(value string) bool {
	var previous rune
	run := 0
	for _, current := range value {
		if run > 0 && current == previous {
			run++
		} else {
			previous = current
			run = 1
		}
		if run > 3 {
			return true
		}
	}

	return false
}
