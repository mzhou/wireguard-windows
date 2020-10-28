/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package syntax

import (
	"errors"
	"strings"
	"syscall"
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
)

type SyntaxEdit struct {
	walk.WidgetBase
	textChangedPublisher            walk.EventPublisher
	privateKeyPublisher             walk.StringEventPublisher
	blockUntunneledTrafficPublisher walk.IntEventPublisher
}

const (
	InevaluableBlockingUntunneledTraffic = 0
	BlockingUntunneledTraffic            = 1
	NotBlockingUntunneledTraffic         = 2
)

func (se *SyntaxEdit) LayoutFlags() walk.LayoutFlags {
	return walk.GrowableHorz | walk.GrowableVert | walk.GreedyHorz | walk.GreedyVert
}

func (se *SyntaxEdit) MinSizeHint() walk.Size {
	return walk.Size{20, 12}
}

func (se *SyntaxEdit) SizeHint() walk.Size {
	return walk.Size{200, 100}
}

func (*SyntaxEdit) CreateLayoutItem(ctx *walk.LayoutContext) walk.LayoutItem {
	return walk.NewGreedyLayoutItem()
}

func (se *SyntaxEdit) Text() string {
	textLength := se.SendMessage(win.WM_GETTEXTLENGTH, 0, 0)
	buf := make([]uint16, textLength+1)
	se.SendMessage(win.WM_GETTEXT, uintptr(textLength+1), uintptr(unsafe.Pointer(&buf[0])))
	return strings.Replace(syscall.UTF16ToString(buf), "\r\n", "\n", -1)
}

func (se *SyntaxEdit) SetText(text string) (err error) {
	if text == se.Text() {
		return nil
	}
	textCRLF := strings.Replace(text, "\n", "\r\n", -1)
	if win.TRUE != se.SendMessage(win.WM_SETTEXT, 0, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(textCRLF)))) {
		err = errors.New("WM_SETTEXT failed")
	}
	se.highlightText(text)
	se.textChangedPublisher.Publish()
	return
}

func (se *SyntaxEdit) TextChanged() *walk.Event {
	return se.textChangedPublisher.Event()
}

func (se *SyntaxEdit) PrivateKeyChanged() *walk.StringEvent {
	return se.privateKeyPublisher.Event()
}

func (se *SyntaxEdit) BlockUntunneledTrafficStateChanged() *walk.IntEvent {
	return se.blockUntunneledTrafficPublisher.Event()
}

func (se *SyntaxEdit) initSyntaxEdit() {
	se.GraphicsEffects().Add(walk.InteractionEffect)
	se.GraphicsEffects().Add(walk.FocusEffect)
	se.MustRegisterProperty("Text", walk.NewProperty(
		func() interface{} {
			return se.Text()
		},
		func(v interface{}) error {
			if s, ok := v.(string); ok {
				return se.SetText(s)
			}
			return se.SetText("")
		},
		se.textChangedPublisher.Event()))
}
