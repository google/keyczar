package org.keyczar.interop;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

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
    Gson gson = new Gson();
    switch (getCommandType(args[0])) {
      case GENERATE:
        // initializes generator from json and then prints output
        Generator generator = gson.fromJson(args[0], Generator.class);
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
        Creator creator = gson.fromJson(args[0], Creator.class);
        creator.create();
        break;
      case TEST:
        // initializes tester from json and then throws error if it fails
        Tester tester = gson.fromJson(args[0], Tester.class);
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
    JsonParser parser = new JsonParser();
    JsonObject object = parser.parse(jsonString).getAsJsonObject();
    return InteropCommand.getCommand(object.get("command").getAsString());
  }
  
  

}
