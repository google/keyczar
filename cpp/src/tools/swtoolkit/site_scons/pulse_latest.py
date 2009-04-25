#!/usr/bin/python2.4
# Copyright 2009, Google Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following disclaimer
# in the documentation and/or other materials provided with the
# distribution.
#     * Neither the name of Google Inc. nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""Module to find the latest green build from Pulse.

This module locates the latest green build from Pulse for download.
"""

import xmlrpclib


def GetLatest(server_url, project_name, username, password,
              command, name, filename, stage):
  """Get the latest version of an artifact from Pulse.

  Args:
    server_url: The pulse server url, for example http://pulse:8080/
    project_name: The  name of the Pulse project to access.
    username: Username for login.
    password: Password for login.
    command: The command the artifact comes from.
    name: The name of the artifact.
    filename: The relative path to the artifact file.
    stage: The stage to grab the artifact from.
  Returns:
    Returns None if nothing is found, otherwise it returns a permalink to the
    artifacts download.
  Raises:
    IOError: In the event of access failure or if no green builds exist.
  """
  server = xmlrpclib.ServerProxy(server_url + 'xmlrpc')
  token = server.RemoteApi.login(username, password)
  # Get the latest 100 builds of the tools.
  builds = server.RemoteApi.getLatestBuildsForProject(token, project_name,
                                                      '', True, 100)

  # Extract the latest green build.
  green_builds = [b for b in builds if b['status'] == 'success']
  if not green_builds:
    raise IOError('No green builds of project %s found' % project_name)
  build = green_builds[0]

  artifacts = server.RemoteApi.getArtifactsInBuild(token, project_name,
                                                   build['id'])
  # Pick out the desired artifact file.
  link = None
  for a in artifacts:
    # Skip everything other than what we're looking for.
    if a['command'] != command or a['name'] != name or a['stage'] != stage:
      continue
    # Construct full permalink to artifact.
    link = (server_url + a['permalink'] + filename)
    break

  server.RemoteApi.logout(token)

  return link
