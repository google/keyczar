package org.keyczar.interop;

import org.keyczar.i18n.Messages;

/**
 * Enum for command word in the json command line arguments
 */
public enum InteropCommand {
  CREATE("create"),
  GENERATE("generate"),
  TEST("test");
  
  private final String name;

  private InteropCommand(String name) {
    this.name = name;
  }

  @Override
  public String toString() {
    return name;
  }

  public static InteropCommand getCommand(String command) {
    if (command == null) {
      throw new NullPointerException();
    }
    if (command.equalsIgnoreCase(CREATE.toString())) {
      return CREATE;
    } else if (command.equalsIgnoreCase(GENERATE.toString())) {
      return GENERATE;
    } else if (command.equalsIgnoreCase(TEST.toString())) {
      return TEST;
    }
    throw new IllegalArgumentException(
        Messages.getString("Command.UnknownCommand", command));
  }
}