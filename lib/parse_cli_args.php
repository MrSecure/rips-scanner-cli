<?php
/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannesdahse@gmx.de)
			
			
Copyright (C) 2010 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.	

This file created by Ben Allen, 2011

**/

/**
 * parse_cli
 * 
 * Set up the RIPS CONFIG array by parsing the command line arguments passed when calling
 * main.php using the 'cli' SAPI
 * 
 * 
 * CONFIG - array of config data
 * ['loc'] - (string) file/directory location to start the scan
 * ['subdirs'] - (bool) if true, recurse into subdirectories (default = FALSE)
 * ['treestyle'] - (int) 1 => bottom-up (default),  2 => top-down
 * ['verbosity'] - (int) 1(default) ... 5(maximum)
 * ['vector'] - (string/enum) server (default), all, code, exec, connect, file_read, file_include, file_affect, 
 *               ldap, database, client, xpath
 * ['search'] - (bool) search code for the regex, rather than scanning the code (default = FALSE)            
 * ['regex'] - (string) regex to use for searching code
 * ['ignore_warning'] - (bool) ignore the "many files" warning - CLI forces TRUE
 */
function parse_cli()
{

	// Set the defaults:
	$conf = array(
		'subdirs' => FALSE, 
		'treestyle' => 1,
		'verbosity' => 2,
	);
	
	$short = "hif:rduv:o:m:";
	
	$long = array(
		'all',			// scan for all vectors
		'cient',		// scan for client-side vectors
		'server',		// scan all server-side ... includes entire list below 
		'code',			
		'file_read',
		'file_include',
		'file_affect',
		'exec',
		'database',
		'xpath',
		'ldap',
		'connect'
	);
	
	$args = getopt($short, $long);
	var_dump($args); echo "\n\n--------------------------\n\n";
	
	if (isset($args['h']) || count($args) == 0) {
		echo <<<ENDHELP
Usage: 
  -h     =>   this help page,  * items are required
  -r     =>   enable recursion
  -i     =>   ignore many files warning
  -u     =>   treestyle: bottom-up
  -d     =>   treestyle: top-down
  -v #   =>   verbosity level 
              1 => User Tainted (default)
              2 => File/DB Tainted + 1
              3 => Show Secured + 2
              4 => Untainted + 3
              5 => Debug
  -o #   =>   Output Verbosity
              1 => Counts by vuln category, statistics
              2 => File Listing + 1
              3 => Vulnerable Call + 2
              4 => Backtraces + 3
    
  -f @   => * location (directory) to scan
  -m @   => * Mode: [all|client|server|code|file_read|file_include|file_affect|exec|database|xpath|ldap|connect]


ENDHELP;
	exit(1);
	}
	
	
	$nvectors = 0;
	foreach ($long as $v) {
		if (isset($args[$v])) {
			if (!isset($conf['vector'])) {
				$conf['vector'] = $v;
			}
		}
	}
	
	if (isset($args['m'])) {
		if (in_array($args['m'], $long)) {
			$conf['vector'] = $args['m'];
		}
	} 
	
	if (!isset($conf['vector'])) {
		$conf['vector'] = 'server';
	}
	
	if (is_readable($args['f'])) {
		$conf['loc'] = $args['f'];
	}
	
	if (isset($args['r'])) {
		$conf['subdirs'] = TRUE;
	}
	
	if (isset($args['i'])) {
		$conf['ignore_warning'] = TRUE;
	}
	
	if (isset($args['d'])) {
		$conf['treestyle'] = 2;
	} else {
		$conf['treestyle'] = 1;
	}
	
	if (isset($args['v'])) {
		$ver = (int) $args['v'];
		if ($ver > 5 || $ver < 1) {
			$conf['verbosity'] = 1;
		} else {
			$conf['verbosity'] = $ver;
		}
	} else {
		$conf['verbosity'] = 1;
	}
	
	if (isset($args['o'])) {
		$ver = (int) $args['o'];
		if ($ver > 4 || $ver < 1) {
			$conf['outv7y'] = 1;
		} else {
			$conf['outv7y'] = $ver;
		}
	} else {
		$conf['outv7y'] = 1;
	}
	
	$conf['mode'] = 'cli';
	$conf['stylesheet'] = 'text';
	// print_r($conf); exit;
	return $conf;
}