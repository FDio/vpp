/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.openvpp.vppjapi;

public class vppInterfaceCounters {

    public long rxOctets;
    public long rxIp4;
    public long rxIp6;
    public long rxUnicast;
    public long rxMulticast;
    public long rxBroadcast;
    public long rxDiscard;
    public long rxFifoFull;
    public long rxError;
    public long rxUnknownProto;
    public long rxMiss;

    public long txOctets;
    public long txIp4;
    public long txIp6;
    public long txUnicast;
    public long txMulticast;
    public long txBroadcast;
    public long txDiscard;
    public long txFifoFull;
    public long txError;
    public long txUnknownProto;
    public long txMiss;

    public vppInterfaceCounters(
            long rxOctets, long rxIp4, long rxIp6, long rxUni, long rxMulti,
            long rxBcast, long rxDiscard, long rxFifoFull, long rxError,
            long rxUnknownProto, long rxMiss,
            long txOctets, long txIp4, long txIp6, long txUni, long txMulti,
            long txBcast, long txDiscard, long txFifoFull, long txError,
            long txUnknownProto, long txMiss)
    {
        this.rxOctets = rxOctets;
        this.rxIp4 = rxIp4;
        this.rxIp6 = rxIp6;
        this.rxUnicast = rxUni;
        this.rxMulticast = rxMulti;
        this.rxBroadcast = rxBcast;
        this.rxDiscard = rxDiscard;
        this.rxFifoFull = rxFifoFull;
        this.rxError = rxError;
        this.rxUnknownProto = rxUnknownProto;
        this.rxMiss = rxMiss;

        this.txOctets = txOctets;
        this.txIp4 = txIp4;
        this.txIp6 = txIp6;
        this.txUnicast = txUni;
        this.txMulticast = txMulti;
        this.txBroadcast = txBcast;
        this.txDiscard = txDiscard;
        this.txFifoFull = txFifoFull;
        this.txError = txError;
        this.txUnknownProto = txUnknownProto;
        this.txMiss = txMiss;
    }
}

