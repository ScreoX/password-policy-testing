package passwordpolicy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validPassword = "He!1loW8"

func TestPasswordPolicyNilPassword(t *testing.T) {
	policy := PasswordPolicy{}

	result, err := policy.Check(nil)

	assert.ErrorIs(t, err, ErrNilPassword)
	assert.Empty(t, result.Violations())
}

func TestPasswordPolicyLength(t *testing.T) {
	policy := PasswordPolicy{}

	for _, testCase := range lengthBoundaryCases() {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := policy.Check(&testCase.password)
			require.NoError(t, err)

			assert.ElementsMatch(t, testCase.violations, result.Violations())
		})
	}
}

func TestPasswordPolicyDigit(t *testing.T) {
	policy := PasswordPolicy{}
	testCases := []struct {
		name     string
		password string
		want     bool
	}{
		{name: "Нарушение добавляется, если цифры нет", password: "He!aloWb", want: true},
		{name: "Нарушение не добавляется, если цифра есть", password: validPassword, want: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := policy.Check(&testCase.password)
			require.NoError(t, err)

			assert.Equal(t, testCase.want, containsViolation(result, NoDigit))
		})
	}
}

func TestPasswordPolicyUppercase(t *testing.T) {
	policy := PasswordPolicy{}
	testCases := []struct {
		name     string
		password string
		want     bool
	}{
		{name: "Нарушение добавляется, если заглавной буквы нет", password: "he!1lowo", want: true},
		{name: "Кириллическая буква не считается латинской", password: "Нe!1lowo", want: true},
		{name: "Нарушение не добавляется, если заглавная буква есть", password: validPassword, want: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := policy.Check(&testCase.password)
			require.NoError(t, err)

			assert.Equal(t, testCase.want, containsViolation(result, NoUpper))
		})
	}
}

func TestPasswordPolicyLowercase(t *testing.T) {
	policy := PasswordPolicy{}
	testCases := []struct {
		name     string
		password string
		want     bool
	}{
		{name: "Нарушение добавляется, если строчной буквы нет", password: "HE!1LOWO", want: true},
		{name: "Кириллическая буква не считается латинской", password: "Hя!1LOWO", want: true},
		{name: "Нарушение не добавляется, если строчная буква есть", password: validPassword, want: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := policy.Check(&testCase.password)
			require.NoError(t, err)

			assert.Equal(t, testCase.want, containsViolation(result, NoLower))
		})
	}
}

func TestPasswordPolicySpecial(t *testing.T) {
	policy := PasswordPolicy{}
	testCases := []struct {
		name     string
		password string
		want     bool
	}{
		{name: "Нарушение добавляется, если разрешённого символа нет", password: "He.1loW8", want: true},
		{name: "Нарушение не добавляется, если разрешённый символ есть", password: validPassword, want: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := policy.Check(&testCase.password)
			require.NoError(t, err)

			assert.Equal(t, testCase.want, containsViolation(result, NoSpecial))
		})
	}
}

func TestPasswordPolicyWhitespace(t *testing.T) {
	policy := PasswordPolicy{}
	testCases := []struct {
		name     string
		password string
		want     bool
	}{
		{name: "Пробел добавляет нарушение", password: "He!1 loW8", want: true},
		{name: "Табуляция добавляет нарушение", password: "He!1\tloW8", want: true},
		{name: "Перевод строки добавляет нарушение", password: "He!1\nloW8", want: true},
		{name: "Другой пробельный символ добавляет нарушение", password: "He!1\u2003loW8", want: true},
		{name: "Нарушение не добавляется без пробельных символов", password: validPassword, want: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := policy.Check(&testCase.password)
			require.NoError(t, err)

			assert.Equal(t, testCase.want, containsViolation(result, HasWhitespace))
		})
	}
}

func TestPasswordPolicyRepeatedRun(t *testing.T) {
	policy := PasswordPolicy{}
	testCases := []struct {
		name       string
		password   string
		isRepeated bool
	}{
		{name: "Повтор 2 раза допустим", password: "He!1llWo", isRepeated: false},
		{name: "Повтор 3 раза добавляет нарушение", password: "He!1lllW", isRepeated: true},
		{name: "Повтор 4 раза добавляет нарушение", password: "He!1llll", isRepeated: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := policy.Check(&testCase.password)
			require.NoError(t, err)

			assert.Equal(t, testCase.isRepeated, containsViolation(result, RepeatedRun))
		})
	}
}

func TestPasswordPolicyContainsLogin(t *testing.T) {
	policy := PasswordPolicy{}
	testCases := []struct {
		name     string
		password string
		login    *string
		want     bool
	}{
		{name: "Непустой логин находится без учёта регистра", password: "He!1Ivan", login: stringPointer("iVaN"), want: true},
		{name: "Нарушение не добавляется, если логин не найден", password: validPassword, login: stringPointer("ivan"), want: false},
		{name: "Правило не применяется для пустого логина", password: validPassword, login: stringPointer(""), want: false},
		{name: "Правило не применяется без логина", password: validPassword, login: nil, want: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := policy.CheckWithLogin(&testCase.password, testCase.login)
			require.NoError(t, err)

			assert.Equal(t, testCase.want, containsViolation(result, ContainsLogin))
		})
	}
}

func TestPasswordPolicyBlacklist(t *testing.T) {
	policy := PasswordPolicy{}
	testCases := []struct {
		name     string
		password string
		want     bool
	}{
		{name: "password находится в списке", password: "password", want: true},
		{name: "qwerty находится в списке", password: "qwerty", want: true},
		{name: "123456 находится в списке", password: "123456", want: true},
		{name: "admin находится в списке", password: "admin", want: true},
		{name: "welcome находится в списке", password: "welcome", want: true},
		{name: "Регистр PaSsWoRd не влияет на проверку", password: "PaSsWoRd", want: true},
		{name: "Регистр QwErTy не влияет на проверку", password: "QwErTy", want: true},
		{name: "Регистр AdMiN не влияет на проверку", password: "AdMiN", want: true},
		{name: "Регистр WeLcOmE не влияет на проверку", password: "WeLcOmE", want: true},
		{name: "Похожий пароль не входит в blacklist", password: "Passw0rd!", want: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := policy.Check(&testCase.password)
			require.NoError(t, err)

			assert.Equal(t, testCase.want, containsViolation(result, Blacklisted))
		})
	}
}

func TestPasswordPolicyMultipleViolations(t *testing.T) {
	policy := PasswordPolicy{}
	password := ""
	result, err := policy.Check(&password)
	require.NoError(t, err)

	assert.ElementsMatch(t, []Violation{
		TooShort,
		NoDigit,
		NoUpper,
		NoLower,
		NoSpecial,
	}, result.Violations())
}

func TestPasswordPolicyResult(t *testing.T) {
	policy := PasswordPolicy{}
	testCases := []struct {
		name       string
		password   string
		isValid    bool
		violations []Violation
	}{
		{name: "Валидный пароль не содержит нарушений", password: validPassword, isValid: true, violations: nil},
		{name: "Пароль с нарушением невалиден", password: "He!aloWb", isValid: false, violations: []Violation{NoDigit}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := policy.Check(&testCase.password)
			soft := assert.New(t)

			soft.NoError(err)
			soft.Equal(testCase.isValid, result.IsValid())
			soft.ElementsMatch(testCase.violations, result.Violations())
		})
	}
}

type lengthBoundaryCase struct {
	name       string
	password   string
	violations []Violation
}

// lengthBoundaryCases использую как аналог MethodSource
func lengthBoundaryCases() []lengthBoundaryCase {
	return []lengthBoundaryCase{
		{name: "Длина 7 слишком короткая", password: "He!1loW", violations: []Violation{TooShort}},
		{name: "Длина 8 допустима", password: validPassword, violations: nil},
		{name: "Длина 64 допустима", password: "He!1" + strings.Repeat("lo", 30), violations: nil},
		{name: "Длина 65 слишком большая", password: "He!1" + strings.Repeat("lo", 30) + "W", violations: []Violation{TooLong}},
	}
}

func containsViolation(result Result, expected Violation) bool {
	for _, violation := range result.Violations() {
		if violation == expected {
			return true
		}
	}
	return false
}

func stringPointer(value string) *string {
	return &value
}
