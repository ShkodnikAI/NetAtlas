package model

import "fmt"

// Class — класс устройства из docs/DECISIONS.md, раздел «Классы устройств».
type Class string

const (
	// ClassManaged — управляемый (агент): полный аудит, исполнение действий.
	ClassManaged Class = "managed"
	// ClassKnownNoAgent — известное без агента: присутствие, трафик, порт.
	ClassKnownNoAgent Class = "known_no_agent"
	// ClassGuest — гость: присутствие и трафик, без тревог.
	ClassGuest Class = "guest"
	// ClassUnknown — неизвестное: оповещение и разбор владельцем.
	ClassUnknown Class = "unknown"
)

// Valid сообщает, что класс входит в четыре допустимых значения.
func (c Class) Valid() bool {
	switch c {
	case ClassManaged, ClassKnownNoAgent, ClassGuest, ClassUnknown:
		return true
	default:
		return false
	}
}

// ParseClass разбирает строку в класс устройства; пустая строка и любое
// значение вне четырёх допустимых дают ошибку.
func ParseClass(s string) (Class, error) {
	c := Class(s)
	if !c.Valid() {
		return "", fmt.Errorf("model: недопустимый класс устройства %q", s)
	}
	return c, nil
}
