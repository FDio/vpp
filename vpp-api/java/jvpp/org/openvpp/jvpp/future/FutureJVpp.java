
package org.openvpp.jvpp.future;


/**
* Future facade on top of JVpp
*/
public interface FutureJVpp {

    /**
    * Invoke asynchronous operation on VPP

    * @return Future that wraps the results of async VPP execution
    */
    <REQ extends org.openvpp.jvpp.dto.JVppRequest, REPLY extends org.openvpp.jvpp.dto.JVppReply<REQ>>
        java.util.concurrent.Future<REPLY> send(REQ req);

}
