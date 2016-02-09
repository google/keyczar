/*
 * Copyright 2013 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
