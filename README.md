# PasswordPolicy testing

Домашнее задание по тестированию `PasswordPolicy` по спецификации. Проект выполнен на Go с разрешения преподавателя

## Артефакты для сдачи

1. [password_policy_test.go](passwordpolicy/password_policy_test.go) - тест-сьют
2. [PasswordPolicyTest-баги.md](PasswordPolicyTest-баги.md) - баг-репорты на найденные расхождения
3. [Исправленный password_policy.go](passwordpolicy/password_policy.go) и [регрессионные тесты на каждый дефект (помечены комментариями)](passwordpolicy/password_policy_test.go)
4. Два скриншота:
   - [дерево отчета Allure](docs/allure-report.png)
   - [покрытие PasswordPolicy](docs/coverage-report.png)
5. Подтверждение порядка «тест до фикса»:
   - [коммит с падающими тестами](https://github.com/ScreoX/password-policy-testing/commit/fd714c2)
   - [следующий коммит с исправлением реализации](https://github.com/ScreoX/password-policy-testing/commit/d2cbfcf)
