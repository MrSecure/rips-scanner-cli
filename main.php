<?php
/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannes.dahse@rub.de)
			

Copyright (C) 2012 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.		

**/

	###############################  INCLUDES  ################################

	include('config/general.php');			// general settings
	include('config/sources.php');			// tainted variables and functions
	include('config/tokens.php');			// tokens for lexical analysis
	include('config/securing.php');			// securing functions
	include('config/sinks.php');			// sensitive sinks
	include('config/info.php');				// interesting functions
	
	include('lib/constructer.php'); 		// classes	
	include('lib/filer.php');				// read files from dirs and subdirs
	include('lib/tokenizer.php');			// prepare and fix token list
	include('lib/analyzer.php');			// string analyzers
	include('lib/scanner.php');				// provides class for scan
	//include('lib/printer.php');				// output scan result
	include('lib/searcher.php');			// search functions
		
	###############################  MAIN  ####################################
	
	// Handle setup of CONFIG array ...
	//  as this was the _POST array before, we can simply copy all of _POST into CONFIG
	//  if we're being called via the web
	// otherwise
	//  process the command line arguments to setup CONFIG
	$CONFIG = array();
	
	if ('cli' == PHP_SAPI) {
		require_once('lib/parse_cli_args.php');
		$CONFIG = parse_cli();
		$CONFIG['output'] = 'text';
	} else {
		$CONFIG = array_merge($_POST);
		$CONFIG['output'] = 'web';
	}
	
	
	// Choose Output Mode & pull in appropriate output functions
	switch($CONFIG['output']) {
		case 'text':
			require_once('lib/printer-text.php');
			break;
		case 'web':	
		default:			
			require_once('lib/printer.php');
			break;
	}
	
	$start = microtime(TRUE);
	
	$output = array();
	$info = array();
	$scanned_files = array();
	
	if(!empty($CONFIG['loc']))
	{		
		$location = realpath($CONFIG['loc']);
		
		if(is_dir($location))
		{
			$scan_subdirs = isset($CONFIG['subdirs']) ? $CONFIG['subdirs'] : false;
			$files = read_recursiv($location, $scan_subdirs);
			
			if(count($files) > WARNFILES && !isset($CONFIG['ignore_warning']))
				die('warning:'.count($files));
		}	
		else if(is_file($location) && in_array(substr($location, strrpos($location, '.')), $FILETYPES))
		{
			$files[0] = $location;
		}
		else
		{
			$files = array();
		}
		
	
		// SCAN
		if(empty($CONFIG['search']))
		{
			$user_functions = array();
			$user_functions_offset = array();
			$user_input = array();
			
			$file_sinks_count = array();
			$count_xss=$count_sqli=$count_fr=$count_fa=$count_fi=$count_exec=$count_code=$count_eval=$count_xpath=$count_ldap=$count_con=$count_other=$count_pop=$count_inc=$count_inc_fail=$count_header=0;
			
			$verbosity = isset($CONFIG['verbosity']) ? $CONFIG['verbosity'] : 1;
			$scan_functions = array();
			$info_functions = Info::$F_INTEREST;
			
			if($verbosity != 5)
			{
				switch($CONFIG['vector']) 
				{
					case 'xss':			$scan_functions = $F_XSS;			break;
					case 'httpheader':	$scan_functions = $F_HTTP_HEADER;	break;
					case 'code': 		$scan_functions = $F_CODE;			break;
					case 'file_read':	$scan_functions = $F_FILE_READ;		break;
					case 'file_affect':	$scan_functions = $F_FILE_AFFECT;	break;		
					case 'file_include':$scan_functions = $F_FILE_INCLUDE;	break;			
					case 'exec':  		$scan_functions = $F_EXEC;			break;
					case 'database': 	$scan_functions = $F_DATABASE;		break;
					case 'xpath':		$scan_functions = $F_XPATH;			break;
					case 'ldap':		$scan_functions = $F_LDAP;			break;
					case 'connect': 	$scan_functions = $F_CONNECT;		break;
					case 'other':		$scan_functions = $F_OTHER;			break;
					case 'unserialize':	{
										$scan_functions = array_merge($F_POP,$F_XSS);				
										$info_functions = Info::$F_INTEREST_POP;
										$source_functions = array('unserialize');
										$verbosity = 2;
										} 
										break;
					case 'all': 
						$scan_functions = array_merge(
							$F_XSS,
							$F_HTTP_HEADER,
							$F_CODE,
							$F_FILE_READ,
							$F_FILE_AFFECT,
							$F_FILE_INCLUDE,
							$F_EXEC,
							$F_DATABASE,
							$F_XPATH,
							$F_LDAP,
							$F_CONNECT,
							$F_OTHER
						); break;
					case 'client':
						$scan_functions = array_merge(
							$F_XSS,
							$F_HTTP_HEADER
						);
						break;	
					default: // all server side
					{ 
						$scan_functions = array_merge(
							$F_CODE,
							$F_FILE_READ,
							$F_FILE_AFFECT,
							$F_FILE_INCLUDE,
							$F_EXEC,
							$F_DATABASE,
							$F_XPATH,
							$F_LDAP,
							$F_CONNECT,
							$F_OTHER
						); break; 
					}
				}
			}	
			
			if($CONFIG['vector'] !== 'unserialize')
			{
				$source_functions = Sources::$F_OTHER_INPUT;
				// add file and database functions as tainting functions
				if( $verbosity > 1 && $verbosity < 5 )
				{
					$source_functions = array_merge(Sources::$F_OTHER_INPUT, Sources::$F_FILE_INPUT, Sources::$F_DATABASE_INPUT);
				}
			}	
					
			$overall_time = 0;
			$timeleft = 0;
			$file_amount = count($files);		
			for($fit=0; $fit<$file_amount; $fit++)
			{
				// for scanning display
				$thisfile_start = microtime(TRUE);
				$file_scanning = $files[$fit];
				
				if ('web' == $CONFIG['output']) {
					echo ($fit) . '|' . $file_amount . '|' . $file_scanning . '|' . $timeleft . '|' . "\n";
					@ob_flush();
					flush();
				}
				
				// scan
				$scan = new Scanner($file_scanning, $scan_functions, $info_functions, $source_functions);
				$scan->parse();
				$scanned_files[$file_scanning] = $scan->inc_map;
				
				$overall_time += microtime(TRUE) - $thisfile_start;
				// timeleft = average_time_per_file * file_amount_left
				$timeleft = round(($overall_time/($fit+1)) * ($file_amount - $fit+1),2);
			}
			#die("done");
			if ('web' == $CONFIG['output']) {
				echo "STATS_DONE.\n";
				@ob_flush();
				flush();
			}
			
		}
		// SEARCH
		else if(!empty($CONFIG['regex']))
		{
			$count_matches = 0;
			$verbosity = 0;
			foreach($files as $file_name)
			{
				searchFile($file_name, $CONFIG['regex']);
			}
		}
	} 
	
	$elapsed = microtime(TRUE) - $start;
	
	################################  RESULT  #################################	
	
/* switch ($CONFIG['output']) {
	case 'text':
		showPage();
		break;
	case 'interactive':
	default:
		showPage();
		// scan result
		
		break;
	}
*/	
	showPage();
