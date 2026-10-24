//go:build windows

// Win32-значок: Shell_NotifyIconW с stock-иконкой, всплывающее
// сообщение при включении, скрытие при выключении. Никакого сбора
// данных в этом процессе нет — только чтение локального файла
// статуса и отображение.
package main

import (
	"errors"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32        = windows.NewLazySystemDLL("user32.dll")
	shell32       = windows.NewLazySystemDLL("shell32.dll")
	procNotify    = shell32.NewProc("Shell_NotifyIconW")
	procRegister  = user32.NewProc("RegisterClassExW")
	procCreate    = user32.NewProc("CreateWindowExW")
	procMsgLoop   = user32.NewProc("GetMessageW")
	procTranslate = user32.NewProc("TranslateMessage")
	procDispatch  = user32.NewProc("DispatchMessageW")
	procLoadIcon  = user32.NewProc("LoadIconW")
	procDefProc   = user32.NewProc("DefWindowProcW")
	procPostQuit  = user32.NewProc("PostQuitMessage")
)

const (
	NIM_ADD         = 0
	NIM_MODIFY      = 1
	NIM_DELETE      = 2
	NIF_MESSAGE     = 1
	NIF_ICON        = 2
	NIF_INFO        = 0x10
	NIF_TIP         = 4
	NIIF_INFO       = 1
	WM_APP          = 0x8000
	WM_USER         = 0x400
	WM_CLOSE        = 0x0010
	WM_DESTROY      = 0x0002
	IDI_INFORMATION = 0x4004
	CS_DEFAULTSTYLE = 0
)

// notifyIconData — SHELL-структура значка (unicode).
type notifyIconData struct {
	CbSize           uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         GUID
	HBalloonIcon     uintptr
}

// GUID — для выравнивания структуры.
type GUID [16]byte

var (
	statusShown    bool
	hwnd           uintptr
	hicon          uintptr
	msgWindowClass = "NetAtlasNotifyWnd"
)

// runLoop — цикл: чтение статуса → показать/скрыть значок; окно
// сообщений крутится в отдельной горутине (Win32 требует).
func runLoop(dir string) error {
	if err := createMessageWindow(); err != nil {
		return err
	}
	go messagePump()
	tick := pollInterval
	shown := false
	everShown := false
	for {
		time.Sleep(tick)
		now := status(dir)
		switch {
		case now && !shown:
			showIcon(!everShown) // первое включение — с уведомлением
			shown, everShown = true, true
		case !now && shown:
			hideIcon()
			shown = false
		}
	}
}

// createMessageWindow — скрытое окно сообщений для значка.
func createMessageWindow() error {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getModule := kernel32.NewProc("GetModuleHandleW")
	hInst, _, _ := getModule.Call()
	classPtr := unsafe.Pointer(windows.StringToUTF16Ptr(msgWindowClass))
	wc := struct {
		style      uint32
		wndProc    uintptr
		clsExtra   int32
		winExtra   int32
		instance   uintptr
		icon       uintptr
		cursor     uintptr
		background uintptr
		menuName   uintptr
		className  uintptr
	}{wndProc: syscall.NewCallback(wndProc), instance: hInst,
		className: uintptr(classPtr)}
	if r, _, err := procRegister.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		if err != nil && err.Error() != "Операция успешно завершена." {
			return err
		}
	}
	hwnd, _, _ = procCreate.Call(0, 0, 0, 0, 0, 0, 0, 0, uintptr(^uintptr(2)), 0, uintptr(classPtr), 0)
	if hwnd == 0 {
		return errors.New("notify: окно сообщений не создано")
	}
	hi, _, _ := procLoadIcon.Call(0, uintptr(IDI_INFORMATION))
	hicon = hi
	return nil
}

// wndProc — минимум: закрытие и пользовательские сообщения значка.
func wndProc(h, m, w, l uintptr) uintptr {
	switch m {
	case WM_DESTROY:
		procPostQuit.Call(0)
		return 0
	}
	r, _, _ := procDefProc.Call(h, m, w, l)
	return r
}

// messagePump — цикл сообщений Win32.
func messagePump() {
	var msg [7]uintptr // MSG
	for {
		r, _, _ := procMsgLoop.Call(uintptr(unsafe.Pointer(&msg[0])), 0, 0, 0)
		if r == 0 {
			return
		}
		procTranslate.Call(uintptr(unsafe.Pointer(&msg[0])))
		procDispatch.Call(uintptr(unsafe.Pointer(&msg[0])))
	}
}

// showIcon — добавить значок; notify=true — с всплывающим текстом.
func showIcon(notify bool) {
	if hwnd == 0 {
		return
	}
	var d notifyIconData
	d.CbSize = uint32(unsafe.Sizeof(d))
	d.HWnd = hwnd
	d.UID = 1
	d.UFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
	d.UCallbackMessage = WM_USER + 1
	d.HIcon = hicon
	copyTip(d.SzTip[:], "ПК под наблюдением: NetAtlas (активность)")
	if notify {
		d.UFlags |= NIF_INFO
		copyTip(d.SzInfoTitle[:], "ПК под наблюдением")
		copyTip(d.SzInfo[:], "На этом компьютере включён сбор активности (NetAtlas). Значок будет виден, пока сбор включён.")
		d.DwInfoFlags = NIIF_INFO
	}
	procNotify.Call(NIM_ADD, uintptr(unsafe.Pointer(&d)))
	statusShown = true
}

// hideIcon — убрать значок.
func hideIcon() {
	if hwnd == 0 {
		return
	}
	var d notifyIconData
	d.CbSize = uint32(unsafe.Sizeof(d))
	d.HWnd = hwnd
	d.UID = 1
	procNotify.Call(NIM_DELETE, uintptr(unsafe.Pointer(&d)))
	statusShown = false
}

// copyTip — строка в фиксированный UTF16-буфер.
func copyTip(dst []uint16, s string) {
	u := utf16(s)
	for i := 0; i < len(dst)-1 && i < len(u); i++ {
		dst[i] = u[i]
	}
}

func utf16(s string) []uint16 {
	return syscall.StringToUTF16(s)
}
