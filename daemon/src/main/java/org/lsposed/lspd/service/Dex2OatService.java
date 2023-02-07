/*
 * This file is part of LSPosed.
 *
 * LSPosed is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LSPosed is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with LSPosed.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2022 LSPosed Contributors
 */

package org.lsposed.lspd.service;

import static org.lsposed.lspd.ILSPManagerService.DEX2OAT_CRASHED;
import static org.lsposed.lspd.ILSPManagerService.DEX2OAT_MOUNT_FAILED;
import static org.lsposed.lspd.ILSPManagerService.DEX2OAT_OK;

import android.net.LocalServerSocket;
import android.os.Build;
import android.os.SELinux;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.Log;

import androidx.annotation.RequiresApi;

import java.io.BufferedReader;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStreamReader;

@RequiresApi(Build.VERSION_CODES.Q)
public class Dex2OatService implements Runnable {
    public static final String PROP_NAME = "dalvik.vm.dex2oat-flags";
    public static final String PROP_VALUE = "--inline-max-code-units=0";
    private static final String TAG = "LSPosedDex2Oat";
    private static final String WRAPPER32 = "bin/dex2oat32";
    private static final String WRAPPER64 = "bin/dex2oat64";

    private final String[] dex2oatArray = new String[4];
    private final FileDescriptor[] fdArray = new FileDescriptor[4];
    private String magiskTmp = null;
    private int compatibility = DEX2OAT_OK;

    private void openDex2oat(int id, String path) {
        try {
            var fd = Os.open(path, OsConstants.O_RDONLY, 0);
            dex2oatArray[id] = path;
            fdArray[id] = fd;
        } catch (ErrnoException ignored) {
        }
    }

    public Dex2OatService() {
        if (Build.VERSION.SDK_INT == Build.VERSION_CODES.Q) {
            openDex2oat(0, "/apex/com.android.runtime/bin/dex2oat");
            openDex2oat(1, "/apex/com.android.runtime/bin/dex2oatd");
        } else {
            openDex2oat(0, "/apex/com.android.art/bin/dex2oat32");
            openDex2oat(1, "/apex/com.android.art/bin/dex2oatd32");
            openDex2oat(2, "/apex/com.android.art/bin/dex2oat64");
            openDex2oat(3, "/apex/com.android.art/bin/dex2oatd64");
        }
    }

    private boolean notMounted() {
        for (int i = 0; i < dex2oatArray.length; i++) {
            var bin = dex2oatArray[i];
            if (bin == null) continue;
            try {
                var apex = Os.stat("/proc/1/root" + bin);
                var wrapper = Os.stat(i < 2 ? WRAPPER32 : WRAPPER64);
                if (apex.st_dev != wrapper.st_dev || apex.st_ino != wrapper.st_ino) {
                    Log.w(TAG, "Check mount failed for " + bin);
                    return true;
                }
            } catch (ErrnoException e) {
                Log.e(TAG, "Check mount failed for " + bin, e);
                return true;
            }
        }
        Log.d(TAG, "Check mount succeeded");
        return false;
    }

    private void doMount(boolean enabled) {
        doMountNative(enabled, magiskTmp, dex2oatArray[0], dex2oatArray[1],
                dex2oatArray[2], dex2oatArray[3]);
    }

    public void start() {
        try {
            var proc = new ProcessBuilder("magisk", "--path").start();
            try (var reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                if (proc.waitFor() == 0) {
                    magiskTmp = reader.readLine();
                    if (magiskTmp.startsWith("/proc/")) magiskTmp = null;
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "no magisk", e);
        }

        if (notMounted()) { // Already mounted when restart daemon
            doMount(true);
            if (notMounted()) {
                doMount(false);
                compatibility = DEX2OAT_MOUNT_FAILED;
                return;
            }
        }

        var thread = new Thread(this);
        thread.setName("dex2oat");
        thread.start();
    }

    @Override
    public void run() {
        Log.i(TAG, "Dex2oat wrapper daemon start");
        var sockPath = getSockPath();
        Log.d(TAG, "wrapper path: " + sockPath);
        var magisk_file = "u:object_r:magisk_file:s0";
        SELinux.setFileContext(WRAPPER32, magisk_file);
        SELinux.setFileContext(WRAPPER64, magisk_file);
        var context = SELinux.checkSELinuxAccess("u:r:installd:s0", magisk_file,
                "unix_stream_socket", "connectto") ? magisk_file : "u:r:installd:s0";
        setSockCreateContext(context);
        try (var server = new LocalServerSocket(sockPath)) {
            setSockCreateContext(null);
            while (true) {
                try (var client = server.accept();
                     var is = client.getInputStream();
                     var os = client.getOutputStream()) {
                    var id = is.read();
                    var fd = new FileDescriptor[]{fdArray[id]};
                    client.setFileDescriptorsForSend(fd);
                    os.write(1);
                    Log.d(TAG, "Sent stock fd: is64 = " + ((id & 0b10) != 0) +
                            ", isDebug = " + ((id & 0b01) != 0));
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Dex2oat wrapper daemon crashed", e);
            if (compatibility == DEX2OAT_OK) {
                doMount(false);
                compatibility = DEX2OAT_CRASHED;
            }
        }
    }

    public int getCompatibility() {
        return compatibility;
    }

    private native void doMountNative(boolean enabled, String magisktmp,
                                      String r32, String d32, String r64, String d64);

    private static native boolean setSockCreateContext(String context);

    private native String getSockPath();
}
