// Command netatlas-pki — управление собственным центром сертификации
// NetAtlas: создание CA и ключа подписи, токены регистрации агентов,
// отзыв сертификатов, экспорт публичных ключей.
//
// Каталог ключей задаётся переменной окружения NETATLAS_KEYDIR
// (обязательна). Закрытые ключи утилита никогда не печатает: вывод —
// только пути, публичные PEM и токен регистрации (один раз). В базе
// остаётся только SHA-256 токена.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/ShkodnikAI/NetAtlas/internal/version"
	"github.com/ShkodnikAI/NetAtlas/pki"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

func main() {
	if err := run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "netatlas-pki: %v\n", err)
		os.Exit(1)
	}
}

// run — исполнение подкоманды; окружение и выводы подменяемы в тестах.
func run(args []string, getenv func(string) string, out, errOut *os.File) error {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "использование: netatlas-pki <init|enroll-token|revoke|export-pub> [аргументы]")
		os.Exit(2)
	}
	if len(args) > 0 && (args[0] == "--version" || args[0] == "-version") {
		fmt.Fprintln(out, version.String())
		return nil
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "init":
		return cmdInit(getenv, out)
	case "enroll-token":
		return cmdEnrollToken(rest, out, errOut)
	case "revoke":
		return cmdRevoke(rest, out)
	case "export-pub":
		return cmdExportPub(getenv, out)
	default:
		return fmt.Errorf("неизвестная подкоманда %q", cmd)
	}
}

// keydir — каталог ключей из окружения; без него утилита не работает
// (переменная обязательна по решению аудитора).
func keydir(getenv func(string) string) (string, error) {
	dir := getenv("NETATLAS_KEYDIR")
	if dir == "" {
		return "", fmt.Errorf("переменная NETATLAS_KEYDIR не задана (каталог ключей обязателен)")
	}
	return dir, nil
}

// cmdInit создаёт каталог ключей: CA (ECDSA P-256) и ключ подписи
// заданий (ed25519). Печатает только имена созданных файлов.
func cmdInit(getenv func(string) string, out *os.File) error {
	dir, err := keydir(getenv)
	if err != nil {
		return err
	}
	if err := pki.InitDir(dir); err != nil {
		return err
	}
	fmt.Fprintf(out, "создан каталог ключей %s: ca.key, ca.pem, sign.key, sign.pub\n", dir)
	fmt.Fprintln(out, "закрытые ключи не печатаются; резервная копия каталога — отдельно от базы (docs/PKI.md)")
	return nil
}

// cmdEnrollToken выдаёт токен регистрации агента: печатается один
// раз, в базе и аудите — только SHA-256.
func cmdEnrollToken(args []string, out, errOut *os.File) error {
	dbPath := flagValue(args, "--db")
	if dbPath == "" {
		return fmt.Errorf("нужен флаг --db <путь к базе>")
	}
	st, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("база: %w", err)
	}
	defer st.Close()
	token, err := st.IssueEnrollToken(context.Background(), "pki-tool")
	if err != nil {
		return err
	}
	// Токен печатается ровно один раз и нигде не сохраняется.
	fmt.Fprintln(out, token)
	fmt.Fprintf(errOut, "токен действителен %s, повторно не показывается; в базе только SHA-256\n", store.EnrollTokenTTL)
	return nil
}

// cmdRevoke отзывает сертификат по серийному номеру (десятичная
// строка): netatlas-pki revoke <serial> --db <путь>.
func cmdRevoke(args []string, out *os.File) error {
	dbPath := flagValue(args, "--db")
	var serial string
	for i, a := range args {
		if a == "--db" {
			i++ // значение флага пропускается
			continue
		}
		if i == 0 {
			serial = a
		}
	}
	if serial == "" {
		return fmt.Errorf("использование: netatlas-pki revoke <серийный номер> --db <путь к базе>")
	}
	if dbPath == "" {
		return fmt.Errorf("нужен флаг --db <путь к базе>")
	}
	st, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("база: %w", err)
	}
	defer st.Close()
	if err := st.RevokeCert(context.Background(), serial, "pki-tool"); err != nil {
		return err
	}
	fmt.Fprintf(out, "сертификат %s отозван\n", serial)
	return nil
}

// cmdExportPub печатает публичные материалы для агентов: открытый
// ключ подписи заданий и сертификат CA. Закрытые ключи не читаются.
func cmdExportPub(getenv func(string) string, out *os.File) error {
	dir, err := keydir(getenv)
	if err != nil {
		return err
	}
	pubPEM, err := os.ReadFile(dir + "/sign.pub")
	if err != nil {
		return fmt.Errorf("pki: чтение открытого ключа подписи: %w", err)
	}
	caPEM, err := os.ReadFile(dir + "/ca.pem")
	if err != nil {
		return fmt.Errorf("pki: чтение сертификата CA: %w", err)
	}
	fmt.Fprintf(out, "%s\n%s", pubPEM, caPEM)
	return nil
}

// flagValue извлекает значение флага "--name value".
func flagValue(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
