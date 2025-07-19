package com.debugthings.ghidra.utilities;

import java.sql.Ref;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.util.CodeUnitInsertionException;

public class Utilities {

    private GhidraScript gs;

    public Utilities(GhidraScript gs) {
        this.gs = gs;

    }

    private String truncateString(String input, int limit) {
        if (input.length() <= limit)
            return input;
        return input.substring(0, limit) + "...";
    }

    /**
     * Adds a memory reference to a string in the DPTR memory space.
     *
     * @param referenceToAddStringRefTo The address where the string reference should be added.
     * @param stringRefAddress           The address of the string in memory.
     * @param primary                    Whether this reference should be marked as primary.
     * @param isRead                     Whether this reference is a read or write operation.
     * @throws CodeUnitInsertionException If there is an error inserting the code unit.
     */
    public void addDPTRMemoryReference(Address referenceToAddStringRefTo, Address stringRefAddress,
            Boolean primary, Boolean isRead) throws CodeUnitInsertionException {
        // This address is the location of the string in the memory space and we can now create the data type for it
        if (stringRefAddress == null || referenceToAddStringRefTo == null) {
            return;
        }

        Reference memoryAddressRef =
            gs.getCurrentProgram()
                    .getReferenceManager()
                    .addMemoryReference(referenceToAddStringRefTo, stringRefAddress,
                        isRead ? RefType.READ : RefType.WRITE,
                        null,
                        0);

        gs.getCurrentProgram().getReferenceManager().setPrimary(memoryAddressRef, primary);

    }

    /**
     * Adds a string reference to the specified address.
     *
     * @param referenceToAddStringRefTo The address where the string reference should be added.
     * @param stringRefAddress           The address of the string in memory.
     * @param primary                    Whether this reference should be marked as primary.
     * @throws CodeUnitInsertionException If there is an error inserting the code unit.
     */
    public void addStringReference(Address referenceToAddStringRefTo, Address stringRefAddress,
            Boolean primary) throws CodeUnitInsertionException {
        // This address is the location of the string in the memory space and we can now create the data type for it
        if (stringRefAddress == null || referenceToAddStringRefTo == null) {
            return;
        }

        Data d = gs.getCurrentProgram().getListing().getDefinedDataAt(stringRefAddress);

        if (d == null) {
            try {
                d = gs.getCurrentProgram()
                        .getListing()
                        .createData(stringRefAddress, new StringDataType());

                if (d.getDataType() instanceof StringDataType) {
                    gs.println(
                        "String data reference added at " + stringRefAddress);
                }
                else {
                    gs.println(
                        "Data at " + stringRefAddress + " is not a StringDataType, it is: " +
                            d.getDataType());
                }
            }
            catch (CodeUnitInsertionException e) {
                // TODO Auto-generated catch block
            }
        }

        Reference stringRef =
            gs.getCurrentProgram()
                    .getReferenceManager()
                    .addMemoryReference(referenceToAddStringRefTo, stringRefAddress, RefType.READ,
                        null,
                        0);
        if (primary) {
            gs.getCurrentProgram().getReferenceManager().setPrimary(stringRef, true);
        }

        Instruction instr =
            gs.getCurrentProgram().getListing().getInstructionAt(referenceToAddStringRefTo);

        if (instr != null) {
            if (d != null && d.getDataType() instanceof StringDataType) {
                instr.setComment(Instruction.PRE_COMMENT,
                    "String reference to: " +
                        truncateString(d.getDefaultValueRepresentation(), 128) +
                        " at " + stringRefAddress);
            }
        }

    }

    public long extractConstantValue(Instruction instr, String registerName) {
        if (instr != null && instr.getInputObjects().length > 0) {
            Object[] r1 = instr.getOpObjects(0);
            //Read each register value from the previous instructions
            if (r1.length != 0 && (r1[0] instanceof Register)) {
                Register reg = (Register) r1[0];
                if (reg.getName().equals(registerName)) {
                    if (instr.getInputObjects().length > 0 &&
                        instr.getInputObjects()[0] instanceof Scalar) {
                        // If the second operand is a scalar, return its value
                        return ((Scalar) instr.getOpObjects(1)[0]).getValue();
                    }
                }
                else {
                    gs.println("Operand is not a register, it is: " + r1[0]);
                    return Long.MIN_VALUE;
                }
            }
        }
        return Long.MIN_VALUE;
    }

    public Address getRefAddress(long r1Value) {
        int addrH = (int) (r1Value >> 16) & 0xFF; // Extract the memory type from R1
        int addrL = (int) (r1Value >> 8) & 0xFF; // Extract the high byte of the address from R1
        int memType = (int) (r1Value & 0xFF); // Extract the low byte of the address from R1

        Address refAddress = null;

        if (memType == 0xff) {
            // Load from the code memory space
            int bank = 1;
            refAddress = gs.getAddressFactory()
                    .getAddressSpace("BANK" + String.format("%02d", bank))
                    .getAddress((addrL << 8) | addrH);
        }
        else if (memType >= 0x82 && memType < 0xfd) {
            // Load from the banked memory space
            int bank = (memType - 1) & 0x3F; // Adjust for the bank offset
            try {
                refAddress = gs.getAddressFactory()
                        .getAddressSpace("BANK" + String.format("%02d", bank))
                        .getAddress((addrL << 8) | addrH);
            }
            catch (Exception e) {
                gs.println("Error getting address for bank " + bank + ": " + e.getMessage());
                return null; // Return null if the address cannot be created
            }
        }
        return refAddress;
    }
    

    public Boolean getValuesFromRegistersR3(Instruction instr) throws CodeUnitInsertionException {
        long r3Value = extractConstantValue(instr, "R3");

        if (r3Value == Long.MIN_VALUE) {
            gs.println("R3 value not found or invalid in (" + instr.getAddress() +
                ") instruction: " + instr);
            return false; // No valid R3 value found

        }
        // Ensure the constant falls within the range
        if (r3Value >= 0x82 && r3Value < 0xC1) {
            // Get next two instructions
            Instruction nextInstr1 = instr.getNext();
            Instruction nextInstr2 = nextInstr1 != null ? nextInstr1.getNext() : null;

            // Extract constants from them
            long r2Value = extractConstantValue(nextInstr1, "R2");
            long r1Value = extractConstantValue(nextInstr2, "R1");
            if (r2Value >= 0x40) {
                long stringAddress = (r1Value << 16) | (r2Value << 8) | r3Value;
                Address stringRefAddress = getRefAddress(stringAddress);
                addStringReference(instr.getAddress(), stringRefAddress, false);
                return true; // Successfully added a string reference
            }
        }
        return false;
    }

    public Boolean getValuesFromRegistersR5(Instruction instr) throws CodeUnitInsertionException {
        long r3Value = extractConstantValue(instr, "R5");

        if (r3Value == Long.MIN_VALUE) {
            gs.println("R0 value not found or invalid in (" + instr.getAddress() +
                ") instruction: " + instr);
            return false; // No valid R3 value found

        }

        // Ensure the constant falls within the range
        if (r3Value >= 0x82 && r3Value < 0xC1) {
            // Get next two instructions
            Instruction nextInstr1 = instr.getPrevious();
            Instruction nextInstr2 = nextInstr1 != null ? nextInstr1.getPrevious() : null;

            // Extract constants from them
            long r2Value = extractConstantValue(nextInstr1, "R4");
            long r1Value = extractConstantValue(nextInstr2, "R0");
            if (r2Value >= 0x40) {
                long stringAddress = (r1Value << 16) | (r2Value << 8) | r3Value;
                Address stringRefAddress = getRefAddress(stringAddress);
                addStringReference(instr.getAddress(), stringRefAddress, false);
                return true; // Successfully added a string reference
            }
        }
        return false;
    }
}