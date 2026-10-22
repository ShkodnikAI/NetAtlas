package arp

import "errors"

// ErrUnsupported — платформа не поддерживает чтение ARP-таблицы.
var ErrUnsupported = errors.New("arp: чтение ARP-таблицы не поддерживается на этой платформе")
