package org.keyczar.interop;

import org.json.JSONException;
import org.json.JSONObject;
import org.keyczar.exceptions.KeyczarException;

/**
 * Command line interop testing tool that takes json parameters
 */
public class Interop {

  /**
   * For use as command line tool.
   * @param args
   */
  public static void main(String[] args) {

    switch (getCommandType(args[0])) {
      case GENERATE:
        // initializes generator from json and then prints output
        Generator generator = Generator.read(args[0]);
        try {
          String output = generator.generate();
          if (output != null) {
            System.out.print(output);
          }
        } catch (KeyczarException e) {
          e.printStackTrace();
          System.exit(1);
        }
        break;
      case CREATE:
        Creator creator = Creator.read(args[0]);
        creator.create();
        break;
      case TEST:
        // initializes tester from json and then throws error if it fails
        Tester tester = Tester.read(args[0]);
        try {
          tester.test();
        } catch (KeyczarException e) {
          e.printStackTrace();
          System.exit(1);
        }
        break;
      default:
        System.out.println("No such command");
        System.exit(1);
    }
  }

  /**
   * Parses the json input and returns the command attribute as an enum
   * @param jsonString
   * @return command enum
   */
  private static InteropCommand getCommandType(String jsonString) {
    try {
      return InteropCommand.getCommand(new JSONObject(jsonString).getString("command"));
    } catch (JSONException e) {
      throw new RuntimeException(e);
    }
  }
}
