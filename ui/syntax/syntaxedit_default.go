// +build !cgo

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 WireGuard LLC. All Rights Reserved.
 */

package syntax

import (
	"strings"
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"
)

func (se *SyntaxEdit) evaluateUntunneledBlocking(cfg string, spans []highlightSpan) {
	state := InevaluableBlockingUntunneledTraffic
	on_allowedips := false
	seen_peer := false
	seen_v6_00 := false
	seen_v4_00 := false
	seen_v6_01 := false
	seen_v6_80001 := false
	seen_v4_01 := false
	seen_v4_1281 := false

	for i := range spans {
		switch spans[i].t {
		case highlightError:
			goto done
		case highlightSection:
			if !strings.EqualFold(cfg[spans[i].s:spans[i].s+spans[i].len], "[Peer]") {
				break
			}
			if !seen_peer {
				seen_peer = true
			} else {
				goto done
			}
			break
		case highlightField:
			on_allowedips = strings.EqualFold(cfg[spans[i].s:spans[i].s+spans[i].len], "AllowedIPs")
			break
		case highlightIP:
			if !on_allowedips || !seen_peer {
				break
			}
			if i+2 >= len(spans) || spans[i+1].t != highlightDelimiter || spans[i+2].t != highlightCidr {
				break
			}
			if spans[i+2].len != 1 {
				break
			}
			switch cfg[spans[i+2].s] {
			case '0':
				switch cfg[spans[i].s : spans[i].s+spans[i].len] {
				case "0.0.0.0":
					seen_v4_00 = true
				case "::":
					seen_v6_00 = true
				}
			case '1':
				switch cfg[spans[i].s : spans[i].s+spans[i].len] {
				case "0.0.0.0":
					seen_v4_01 = true
				case "128.0.0.0":
					seen_v4_1281 = true
				case "::":
					seen_v6_01 = true
				case "8000::":
					seen_v6_80001 = true
				}
			}
			break
		}
	}

	if seen_v4_00 || seen_v6_00 {
		state = BlockingUntunneledTraffic
	} else if (seen_v4_01 && seen_v4_1281) || (seen_v6_01 && seen_v6_80001) {
		state = NotBlockingUntunneledTraffic
	}

done:
	se.blockUntunneledTrafficPublisher.Publish(state)
}

func (se *SyntaxEdit) highlightText(cfg string) {
	spans := highlightConfig(cfg)
	se.evaluateUntunneledBlocking(cfg, spans)
	for i := range spans {
		if spans[i].t == highlightPrivateKey {
			privateKey := cfg[spans[i].s : spans[i].s+spans[i].len]
			se.privateKeyPublisher.Publish(privateKey)
			return
		}
	}
	se.privateKeyPublisher.Publish("")
}

func (*SyntaxEdit) NeedsWmSize() bool {
	return true
}

func (se *SyntaxEdit) WndProc(hwnd win.HWND, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case win.WM_COMMAND:
		switch win.HIWORD(uint32(wParam)) {
		case win.EN_CHANGE:
			se.textChangedPublisher.Publish()
			se.highlightText(se.Text())
		}

	case win.WM_PASTE:
		if !win.OpenClipboard(hwnd) {
			break
		}
		defer win.CloseClipboard()
		handle := win.GetClipboardData(win.CF_UNICODETEXT)
		if handle == 0 {
			break
		}
		p := win.GlobalLock(win.HGLOBAL(handle))
		if p == nil {
			break
		}
		defer win.GlobalUnlock(win.HGLOBAL(p))
		text := windows.UTF16PtrToString((*uint16)(p))
		text = strings.Replace(text, "\r\n", "\n", -1)
		text = strings.Replace(text, "\n", "\r\n", -1)
		win.SendMessage(hwnd, win.EM_REPLACESEL, uintptr(1), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(text))))
		return 0

	case win.WM_GETDLGCODE:
		if wParam == win.VK_RETURN {
			return win.DLGC_WANTALLKEYS
		}
		return win.DLGC_HASSETSEL | win.DLGC_WANTARROWS | win.DLGC_WANTCHARS
	}

	return se.WidgetBase.WndProc(hwnd, msg, wParam, lParam)
}

func NewSyntaxEdit(parent walk.Container) (*SyntaxEdit, error) {
	se := &SyntaxEdit{}
	if err := walk.InitWidget(
		se,
		parent,
		"EDIT",
		win.ES_MULTILINE|win.WS_VISIBLE|win.WS_VSCROLL|win.WS_BORDER|win.WS_HSCROLL|win.WS_TABSTOP|win.ES_WANTRETURN,
		0); err != nil {
		return nil, err
	}
	se.initSyntaxEdit()
	return se, nil
}
