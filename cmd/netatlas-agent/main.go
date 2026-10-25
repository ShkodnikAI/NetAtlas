// Command netatlas-agent — агент NetAtlas (NR-006): регистрация на
// сервере и отправка инвентаря (только чтение). Ничего не исполняет,
// ничего не слушает: исходящие mTLS-соединения к серверу — единственный
// канал. Режимы: enroll, run (служба на Windows, консоль иначе),
// install/uninstall/status (только Windows).
//
// Токен регистрации задаётся флагом --token, используется один раз и
// не сохраняется и не логируется.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ShkodnikAI/NetAtlas/agent"
	"github.com/ShkodnikAI/NetAtlas/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "enroll":
		err = cmdEnroll(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "install":
		err = cmdInstall(os.Args[2:])
	case "uninstall":
		err = cmdUninstall(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "version", "--version", "-version":
		fmt.Println(version.String())
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "netatlas-agent: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `netatlas-agent — агент NetAtlas (только чтение)

Режимы:
  enroll    --server URL --token TOKEN --ca CA.pem [--dir DIR]
  run       --server URL [--dir DIR] [--once] [--dry] [--interval 15m]
  install   --server URL [--dir DIR]   (только Windows, нужны права администратора)
  uninstall                             (только Windows)
  status                                (только Windows)

Каталог состояния по умолчанию: %%ProgramData%%\NetAtlas\agent (Windows)
или ~/.netatlas-agent; переопределяется --dir или NETATLAS_AGENT_DIR.
`)
}

// commonFlags — общие флаги (--server, --dir).
type commonFlags struct {
	server string
	dir    string
}

// parseCommon возвращает указатель: FlagSet.StringVar держит
// указатели на поля структуры, возврат по значению давал копию с
// незаполненным server (найдено E2E NR-029, до этого CLI-слой не
// был покрыт сквозным тестом).
func parseCommon(args []string) (*flag.FlagSet, *commonFlags) {
	fs := flag.NewFlagSet("netatlas-agent", flag.ContinueOnError)
	fs.SetOutput(nil)
	c := &commonFlags{}
	fs.StringVar(&c.server, "server", "", "адрес агентского API сервера (https://...)")
	fs.StringVar(&c.dir, "dir", agent.DefaultDir(), "каталог состояния агента")
	return fs, c
}

// cmdEnroll — регистрация: CA копируется в каталог состояния, ключ
// и сертификат сохраняются; токен не сохраняется.
func cmdEnroll(args []string) error {
	fs, c := parseCommon(args)
	token := fs.String("token", "", "одноразовый токен регистрации (от владельца)")
	ca := fs.String("ca", "", "путь к корневому сертификату сервера (ca.pem)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if c.server == "" || *token == "" || *ca == "" {
		return fmt.Errorf("нужны --server, --token и --ca")
	}
	id, err := agent.Enroll(context.Background(), c.server, *token, c.dir, *ca)
	if err != nil {
		return err
	}
	// Токен после выхода из cmdEnroll не используется нигде.
	*token = ""
	fmt.Printf("агент зарегистрирован: %s\n", id)
	fmt.Println("запуск: netatlas-agent run --server " + c.server)
	return nil
}

// cmdRun — рабочий цикл. --once --dry: собрать и напечатать отчёт
// без сети (проверка сборщиков на CI). --once: один цикл с сетью.
func cmdRun(args []string) error {
	fs, c := parseCommon(args)
	once := fs.Bool("once", false, "один цикл и выход")
	dry := fs.Bool("dry", false, "без сети: только сбор и печать отчёта")
	interval := fs.Duration("interval", 0, "базовый интервал опроса (по умолчанию — от сервера)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dry {
		body, err := agent.CollectOnce(nil)
		if err != nil {
			return err
		}
		// Проверки безопасности (NR-010): тоже только сбор, без сети.
		sec, err := agent.CollectSecurityOnce(nil)
		if err != nil {
			return err
		}
		out, err := json.Marshal(map[string]json.RawMessage{
			"inventory": body,
			"security":  sec,
		})
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	}
	if c.server == "" {
		return fmt.Errorf("нужен --server")
	}
	// На Windows при запуске из SCM флаги приходят от службы.
	if isSvc, err := agent.IsWindowsService(); err == nil && isSvc {
		return agent.RunService(c.server, c.dir)
	}
	runner, err := agent.NewRunner(c.server, c.dir)
	if err != nil {
		return err
	}
	if *interval > 0 {
		runner.Interval = *interval
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *once {
		return runner.RunOnce(ctx)
	}
	return runner.Run(ctx)
}

// cmdInstall — установка службы (Windows, права администратора).
func cmdInstall(args []string) error {
	fs, c := parseCommon(args)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if c.server == "" {
		return fmt.Errorf("нужен --server")
	}
	if err := agent.EnsureDir(c.dir); err != nil {
		return err
	}
	if err := agent.Install(c.server, c.dir); err != nil {
		return err
	}
	fmt.Printf("служба установлена (остановлена): запустите вручную или netatlas-agent status\n")
	return nil
}

func cmdUninstall(args []string) error {
	if err := agent.Uninstall(); err != nil {
		return err
	}
	fmt.Println("служба удалена")
	return nil
}

func cmdStatus(args []string) error {
	st, err := agent.StatusState()
	if err != nil {
		return err
	}
	fmt.Println(st)
	return nil
}
