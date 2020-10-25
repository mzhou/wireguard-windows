// +build !cgo

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package version

import (
	"fmt"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun/wintun/resource"
)

var (
	cachedVersion string
	mutex         sync.Mutex
	initialized   uint32
)

func Number() string {
	if atomic.LoadUint32(&initialized) != 0 {
		return cachedVersion
	}
	mutex.Lock()
	defer mutex.Unlock()
	cachedVersion = "<unknown>"
	for {
		const ourModule windows.Handle = 0
		resInfo, err := resource.FindByID(ourModule, resource.VS_VERSION_INFO, resource.RT_VERSION)
		if err != nil {
			break
		}
		data, err := resource.Load(ourModule, resInfo)
		if err != nil {
			break
		}
		dataMutable := make([]byte, len(data))
		copy(dataMutable, data)
		ffi, err := resource.VerQueryRootValue(dataMutable)
		if err != nil {
			break
		}
		ver := [4]uint16{
			uint16((ffi.FileVersionMS & 0xffff0000) >> 16),
			uint16(ffi.FileVersionMS & 0x0000ffff),
			uint16((ffi.FileVersionLS & 0xffff0000) >> 16),
			uint16(ffi.FileVersionLS & 0x0000ffff),
		}
		if ver[3] != 0 {
			cachedVersion = fmt.Sprintf("%d.%d.%d.%d", ver[0], ver[1], ver[2], ver[3])
		} else if ver[2] != 0 {
			cachedVersion = fmt.Sprintf("%d.%d.%d", ver[0], ver[1], ver[2])
		} else {
			cachedVersion = fmt.Sprintf("%d.%d", ver[0], ver[1])
		}
		break
	}
	atomic.StoreUint32(&initialized, 1)
	return cachedVersion
}
