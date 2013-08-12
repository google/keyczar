package org.keyczar.interop;

import org.keyczar.KeyczarTool;

import java.util.List;

/**
 * Class used for gson data to call create commands
 */
public class Creator {
  @SuppressWarnings("unused")
  private final String command;
  private final List<String> createFlags;
  private final List<String> addKeyFlags;
  
  public Creator(String command, List<String> createFlags, List<String> addKeyFlags) {
    this.command = command;
    this.createFlags = createFlags;
    this.addKeyFlags = addKeyFlags;
  }
  
  public void create() {
    String [] createArgs = createFlags.toArray(new String[createFlags.size()]);
    KeyczarTool.main(createArgs);
    String [] addKeyArgs = addKeyFlags.toArray(new String[addKeyFlags.size()]);
    KeyczarTool.main(addKeyArgs);
  }
}
