/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package syntax

import (
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
)

// #cgo LDFLAGS: -lgdi32
// #include "syntaxedit.h"
import "C"

func (se *SyntaxEdit) highlightText(cfg string) {
}

func (se *SyntaxEdit) WndProc(hwnd win.HWND, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case win.WM_NOTIFY, win.WM_COMMAND:
		switch win.HIWORD(uint32(wParam)) {
		case win.EN_CHANGE:
			se.textChangedPublisher.Publish()
		}
		// This is a horrible trick from MFC where we reflect the event back to the child.
		se.SendMessage(msg+C.WM_REFLECT, wParam, lParam)
	case C.SE_PRIVATE_KEY:
		if lParam == 0 {
			se.privateKeyPublisher.Publish("")
		} else {
			se.privateKeyPublisher.Publish(C.GoString((*C.char)(unsafe.Pointer(lParam))))
		}
	case C.SE_TRAFFIC_BLOCK:
		se.blockUntunneledTrafficPublisher.Publish(int(lParam))
	}
	return se.WidgetBase.WndProc(hwnd, msg, wParam, lParam)
}

func NewSyntaxEdit(parent walk.Container) (*SyntaxEdit, error) {
	C.register_syntax_edit()
	se := &SyntaxEdit{}
	err := walk.InitWidget(
		se,
		parent,
		"WgQuickSyntaxEdit",
		C.SYNTAXEDIT_STYLE,
		C.SYNTAXEDIT_EXTSTYLE,
	)
	if err != nil {
		return nil, err
	}
	se.SendMessage(C.SE_SET_PARENT_DPI, uintptr(parent.DPI()), 0)
	se.initSyntaxEdit()
	return se, nil
}

func (se *SyntaxEdit) ApplyDPI(dpi int) {
	se.SendMessage(C.SE_SET_PARENT_DPI, uintptr(dpi), 0)
}
