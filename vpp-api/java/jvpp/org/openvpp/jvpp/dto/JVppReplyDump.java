
package org.openvpp.jvpp.dto;

/**
* Base interface for all dump replies
*/
public interface JVppReplyDump<REQ extends org.openvpp.jvpp.dto.JVppRequest, RESP extends org.openvpp.jvpp.dto.JVppReply<REQ>>
    extends org.openvpp.jvpp.dto.JVppReply<REQ> {

}
