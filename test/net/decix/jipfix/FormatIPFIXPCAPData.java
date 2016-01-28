package net.decix.jipfix;

import net.decix.jipfix.header.DataRecord;
import net.decix.jipfix.header.L2IPDataRecord;
import net.decix.jipfix.header.MessageHeader;
import net.decix.jipfix.header.SetHeader;
import net.decix.util.HeaderParseException;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;

import java.io.FileWriter;
import java.io.IOException;


public class FormatIPFIXPCAPData {  
	private static final String PCAP_FILE_READ = "/Users/glex/Downloads/test.pcap";
	private static final String IPFIX_FILE_WRITE = "/Users/glex/Documents/jflowlib-fork/jFlowLib/test/net/decix/jipfix/data/test_ipfix.csv";
	private static final String COMMA_DELIMITER = ",";
	private static final String NEW_LINE_SEPARATOR = "\n";
	private static FileWriter fileWriter = null;
	private static final boolean ANONYMIZE = false;
	
	
	public static void main(String[] args) throws PcapNativeException, NotOpenException, InterruptedException {
		PcapHandle handleRead = Pcaps.openOffline(PCAP_FILE_READ);
		
		try{
			fileWriter = new FileWriter(IPFIX_FILE_WRITE);
			PacketListener listener = new PacketListener() {	
				public void gotPacket(Packet fullPacket) {
//						System.out.println(packet);
					UdpPacket udpPacket = fullPacket.get(UdpPacket.class);
					if (udpPacket == null) return;
//						System.out.println(packet);
					
					byte[] bytes = udpPacket.getRawData();
					byte[] onlyIPFIX = new byte[bytes.length - 8];
					System.arraycopy(bytes, 8, onlyIPFIX, 0, bytes.length - 8);

					try {
						MessageHeader mh = MessageHeader.parse(onlyIPFIX);
						//System.out.println(mh);
						
//							if (onlyIPFIX.length != mh.getBytes().length) {
//								System.out.println("Length: OnlyIPFIX: " + onlyIPFIX.length + " : Generated: " + mh.getBytes().length);
//							}

						boolean containsOtherThan306SetID = false;
					 	for (SetHeader sh : mh.getSetHeaders()) {
							if (sh.getSetID() != 306) containsOtherThan306SetID = true;
						}
						if (containsOtherThan306SetID) {
							//System.out.printf("frame #%d%n", packet.getFrameNumber());
							//System.out.println("Template?");
						} else {
							for (SetHeader sh : mh.getSetHeaders()) {
								for (DataRecord dr : sh.getDataRecords()) {
									if (dr instanceof L2IPDataRecord) {
										L2IPDataRecord lidr = (L2IPDataRecord) dr;
										String out = parseL2IPData(lidr, ANONYMIZE);
										fileWriter.append(out);
										
										System.out.println(lidr);
										
										
									}
								}
							}
						}
					} catch (HeaderParseException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			};
			
			handleRead.loop(-1, listener);
			handleRead.close();	
			
		}catch (Exception e) {
			System.out.println("Error in CsvFileWriter !!!");
			e.printStackTrace();
		} finally {
			
			try {
				fileWriter.flush();
				fileWriter.close();
			} catch (IOException e) {
				System.out.println("Error while flushing/closing fileWriter !!!");
                e.printStackTrace();
			}
			
		}
			
	} 
		

	protected static String parseL2IPData(L2IPDataRecord lidr, boolean ANONYMIZE) {
		// Format: 
		// SourceMacAddress, DestinationMacAddress, IngressPhysicalInterface, EgressPhysicalInterface, Dot1qVlanId, Dot1qCustomerVlanId, 
		// PostDot1qVlanId, PostDot1qCustomerVlanId, SourceIPv4Address, DestinationIPv4Address, SourceIPv6Address, DestinationIPv6Address, 
		// PacketDeltaCount, OctetDeltaCount, FlowStartMilliseconds, FlowEndMilliseconds, SourceTransportPort, DestinationTransportPort, 
		// TcpControlBits, ProtocolIdentifier, Ipv6ExtensionHeaders, NextHeaderIPv6, FlowLabelIPv6, IpClassOfService, IpVersion, IcmpTypeCodeIPv4
		StringBuilder sb = new StringBuilder();
		
		sb.append(String.valueOf(lidr.getFlowStartMilliseconds()));
		sb.append(COMMA_DELIMITER);
		
		sb.append(String.valueOf(lidr.getFlowEndMilliseconds()));
		sb.append(COMMA_DELIMITER);
		
		sb.append(String.valueOf(lidr.getProtocolIdentifier()));
		sb.append(COMMA_DELIMITER);
		
		if (ANONYMIZE){
			sb.append(String.valueOf(lidr.getSourceIPv4Address().getHostAddress().replaceAll(".\\d{1,3}$", ".1")));			
		}else {
			sb.append(String.valueOf(lidr.getSourceIPv4Address().getHostAddress()));
		}
		sb.append(COMMA_DELIMITER);
		
		sb.append(String.valueOf(lidr.getSourceTransportPort()));
		sb.append(COMMA_DELIMITER);
		
		if (ANONYMIZE){
			sb.append(String.valueOf(lidr.getDestinationIPv4Address().getHostAddress().replaceAll(".\\d{1,3}$", ".1")));			
		}else {
			sb.append(String.valueOf(lidr.getDestinationIPv4Address().getHostAddress()));			
		}
		sb.append(COMMA_DELIMITER);
		
		sb.append(String.valueOf(lidr.getDestinationTransportPort()));
		sb.append(COMMA_DELIMITER);
		
		sb.append(String.valueOf(lidr.getPacketDeltaCount()));
		sb.append(COMMA_DELIMITER);
		
		sb.append(String.valueOf(lidr.getOctetDeltaCount()));
		sb.append(COMMA_DELIMITER);
		
		sb.append(String.valueOf(lidr.getTcpControlBits()));
		sb.append(COMMA_DELIMITER);
		
		sb.append(String.valueOf(lidr.getSourceMacAddress()));
		sb.append(COMMA_DELIMITER);
		
		sb.append(String.valueOf(lidr.getDestinationMacAddress()));
		sb.append(COMMA_DELIMITER);
		
		sb.append(String.valueOf(lidr.getIngressPhysicalInterface()));
		sb.append(COMMA_DELIMITER);
		
		sb.append(String.valueOf(lidr.getEgressPhysicalInterface()));
		sb.append(COMMA_DELIMITER);
		
		sb.append(String.valueOf(lidr.getIpClassOfService()));
		sb.append(COMMA_DELIMITER);
		
		sb.append(String.valueOf(lidr.getIpVersion()));
		sb.append(COMMA_DELIMITER);
		
		sb.append(String.valueOf(lidr.getIcmpTypeCodeIPv4()));
		sb.append(NEW_LINE_SEPARATOR);
		
		return sb.toString();
	}  
}  
