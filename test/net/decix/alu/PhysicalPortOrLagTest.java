package net.decix.alu;

import junit.framework.TestCase;

public class PhysicalPortOrLagTest extends TestCase {
	
	public void testParse() {
		// Physical port
		net.decix.alu.PhysicalPortOrLag ppol = net.decix.alu.PhysicalPortOrLag.parse(1611170072);
		assertTrue(ppol.isPhysicalPort());
		assertFalse(ppol.isLag());
		assertEquals(0, ppol.getLagId());
		assertEquals(2, ppol.getSlot());
		assertEquals(2, ppol.getMda());
		assertEquals(35, ppol.getPort());
		
		// Lag
		ppol = net.decix.alu.PhysicalPortOrLag.parse(1342177336);
		assertFalse(ppol.isPhysicalPort());
		assertTrue(ppol.isLag());
		assertEquals(56, ppol.getLagId());
		assertEquals(0, ppol.getSlot());
		assertEquals(0, ppol.getMda());
		assertEquals(0, ppol.getPort());
	}
	
	public void testToInterfaceIndex() {
		// Physical port
		net.decix.alu.PhysicalPortOrLag ppol = net.decix.alu.PhysicalPortOrLag.parse(1611170072);
		assertEquals(1611170072, ppol.toInterfaceIndex());
		
		// Lag
		ppol = net.decix.alu.PhysicalPortOrLag.parse(1342177336);
		assertEquals(1342177336, ppol.toInterfaceIndex());
	}
}
