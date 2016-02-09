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

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.keyczar.KeyczarTool;

import java.util.ArrayList;
import java.util.List;

/**
 * Class used for json data to call create commands
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

  static Creator read(String jsonString) {
    try {
      JSONObject json = new JSONObject(jsonString);
      return new Creator(
          json.optString("command"),
          buildKeyczartCommands(json.optJSONArray("keyczartCommands")));
    } catch (JSONException e) {
      throw new RuntimeException(e);
    }
  }

  private static List<List<String>> buildKeyczartCommands(JSONArray jsonArray)
      throws JSONException {
    List<List<String>> list = new ArrayList<List<String>>();
    if (jsonArray != null) {
      int max = jsonArray.length();
      for (int i = 0; i < max; i++) {
        JSONArray innerListJsonArray = jsonArray.optJSONArray(i);
        list.add(toListOfStrings(innerListJsonArray));
      }
    }
    return list;
  }

  private static List<String> toListOfStrings(JSONArray jsonArray) throws JSONException {
    List<String> list = new ArrayList<String>();
    if (jsonArray != null) {
      int max = jsonArray.length();
      for (int i = 0; i < max; i++) {
        list.add(jsonArray.getString(i));
      }
    }
    return list;
  }
}
