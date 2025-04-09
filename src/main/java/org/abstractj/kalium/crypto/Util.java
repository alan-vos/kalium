/**
 * Copyright 2013 Bruno Oliveira, and individual contributors
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.abstractj.kalium.crypto;

import java.util.Arrays;

@SuppressWarnings("unused")
public class Util {

    private Util() {
        // Private constructor
    }

    public static byte[] prependZeros(final int n,
                                      final byte[] message) {
        final byte[] result = new byte[n + message.length];
        System.arraycopy(message, 0, result, n, message.length);
        return result;
    }

    public static byte[] removeZeros(final int n,
                                     final byte[] message) {
        return Arrays.copyOfRange(message, n, message.length);
    }

    public static void checkLength(final byte[] data,
                                   final int size) {
        if (data == null || data.length != size)
            throw new RuntimeException("Invalid size");
    }

    public static byte[] zeros(final int n) {
        return new byte[n];
    }

    public static boolean isValid(final int status,
                                  final String message) {
        if (status != 0)
            throw new RuntimeException(message);
        return true;
    }

    public static byte[] slice(byte[] buffer, int start, int end) {
        return Arrays.copyOfRange(buffer, start, end);
    }

    public static byte[] merge(final byte[] signature,
                               final byte[] message) {
        final byte[] result = new byte[signature.length + message.length];
        System.arraycopy(signature, 0, result, 0, signature.length);
        System.arraycopy(message, 0, result, signature.length, message.length);
        return result;
    }
}
