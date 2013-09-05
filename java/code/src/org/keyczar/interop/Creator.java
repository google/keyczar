package org.keyczar.interop;

import org.keyczar.KeyczarTool;

import java.util.List;

/**
 * Class used for gson data to call create commands
 */
public class Creator {
  @SuppressWarnings("unused")
  private final String command;
  private final List<List<String>> keyczartCommands;
  
  public Creator(String command, List<List<String>> keyczartCommands) {
    this.command = command;
    this.keyczartCommands = keyczartCommands;
  }
  
  public void create() {
    for (List<String> keyczartCommand : keyczartCommands) {
      String [] args = keyczartCommand.toArray(new String[keyczartCommand.size()]);
      KeyczarTool.main(args);
    }
  }
}
