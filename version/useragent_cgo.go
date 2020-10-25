/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package version

// #include "version.h"
import "C"

func Number() string {
	return C.WIREGUARD_WINDOWS_VERSION_STRING
}
