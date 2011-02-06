// Copyright 2010 The Walk Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package walk

import (
	"os"
	"syscall"
)

import (
	. "walk/winapi/user32"
)

type TextEdit struct {
	WidgetBase
}

func NewTextEdit(parent IContainer) (*TextEdit, os.Error) {
	if parent == nil {
		return nil, newError("parent cannot be nil")
	}

	hWnd := CreateWindowEx(
		WS_EX_CLIENTEDGE, syscall.StringToUTF16Ptr("EDIT"), nil,
		ES_MULTILINE|ES_WANTRETURN|WS_CHILD|WS_TABSTOP|WS_VISIBLE|WS_VSCROLL,
		0, 0, 160, 80, parent.BaseWidget().hWnd, 0, 0, nil)
	if hWnd == 0 {
		return nil, lastError("CreateWindowEx")
	}

	te := &TextEdit{WidgetBase: WidgetBase{hWnd: hWnd, parent: parent}}
	te.SetFont(defaultFont)

	widgetsByHWnd[hWnd] = te

	parent.Children().Add(te)

	return te, nil
}

func (*TextEdit) LayoutFlags() LayoutFlags {
	return ShrinkHorz | GrowHorz | ShrinkVert | GrowVert
}

func (te *TextEdit) PreferredSize() Size {
	return te.dialogBaseUnitsToPixels(Size{100, 100})
}
