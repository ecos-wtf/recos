//Rename labels pointing to C++ classes vtable by inspecting the name
//of the first functions they point to.
//
//If you launched the auto-renaming scripts, functions will be named like
//BcmEcosSocket::Close, which means we can rename the vtable label from
//PTR_XXX to BcmEcosSocket::vftable.
//
//@author Quentin Kaiser <quentin@ecos.wtf> 
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.database.symbol.TypeFilteredSymbolIterator;
import ghidra.program.model.address.*;

public class RenameLabelVTable extends GhidraScript {

    public void run() throws Exception {

    	SymbolTable symbolTable = currentProgram.getSymbolTable();
    	SymbolIterator symbolIterator = symbolTable.getAllSymbols(true);
    	ReferenceManager refmanager = currentProgram.getReferenceManager();
		ReferenceIterator referenceIter;
    	Reference reference;
    	Function caller;
    	String callerName;
    	String newName;
    	
    	while(symbolIterator.hasNext()) {
    		Symbol symbol = symbolIterator.next();
    		if(symbol.getSymbolType() == SymbolType.LABEL && symbol.getName().contains("PTR_FUN")) {
    			referenceIter = refmanager.getReferencesTo(symbol.getAddress());
    			while(referenceIter.hasNext()) {
    				reference = referenceIter.next();
    				caller = getFunctionContaining(reference.getFromAddress());
    				
    				if(caller != null && !caller.getName().contains("FUN_")) {
    					if(!caller.getName().contains("_")) {
    						
    						printf("[-] %s\n", caller.getName(true));
    						if(symbol.getName(true).contains("::")) {
    							callerName = symbol.getName(true);
    						}else {
    							callerName = caller.getName().replace("~", "");
    							printf("[+] Renaming %s to %s\n", symbol.getName(), callerName + "::vftable");
        						symbol.setName(callerName + "::vftable", SourceType.ANALYSIS);
    						}
    						
    						Address address = symbol.getAddress();
    						Reference[] references;
    						boolean should_continue = true;
    						int index = 1;
    						while(should_continue) {
    							references = refmanager.getReferencesFrom(address);
    							if(references.length == 0) {
    								should_continue = false;
    							}
    							for(int i=0; i < references.length; i++) {
        							Function fun = getFunctionContaining(references[i].getToAddress());
        							if(fun != null) {
        								if(!fun.getName(true).contains("::")) {
        									// the two first functions in vtable are always constructors
        									if(fun.getName().contains("FUN_") && index < 3) {
        										newName = callerName + "::~" + callerName;
        									} else {
        										newName = callerName + "::" + fun.getName();
        									}
        									printf("  %s\n", newName);
        									fun.setName(newName, SourceType.ANALYSIS);
        								} else {
        									printf("  %s\n", fun.getName(true));
        								}
        							}
        						}
    							address = address.add(4);
    							index += 1;
    						}
    					}
    				}  				
    			}
    		}
    	}
    }

}
