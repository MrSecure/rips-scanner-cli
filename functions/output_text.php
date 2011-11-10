<?php
/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannesdahse@gmx.de)
			
			
Copyright (C) 2010 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.	

**/
		
	// reference function declaration with function calls
	function makefunclink($line, $linenr, $funcname)
	{
			$link = ' '.$funcname.' ';
			// $link.= '<a href="#'.$funcname.'_call" title="jump to call">';
			// $link.= highlightline($line, $linenr).'</a>';
			return $link;
	}
	
	// prepare output to style with CSS
	function highlightline($line, $line_nr, $title=false, $udftitle=false, $tainted_vars=array())
	{
		return $line_nr . ': ' . $line;
	}
	
	// detect vulnerability type given by the PVF name
	// note: same names are used in help.php!
	function getVulnNodeTitleX($func_name)
	{
		if(isset($GLOBALS['F_XSS'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_XSS'];  }	
		else if(isset($GLOBALS['F_DATABASE'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_DATABASE'];  }	
		else if(isset($GLOBALS['F_FILE_READ'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_FILE_READ'];  }
		else if(isset($GLOBALS['F_FILE_AFFECT'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_FILE_AFFECT'];  }		
		else if(isset($GLOBALS['F_FILE_INCLUDE'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_FILE_INCLUDE'];  }	 		
		else if(isset($GLOBALS['F_EXEC'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_EXEC'];  }
		else if(isset($GLOBALS['F_CODE'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_CODE'];  }
		else if(isset($GLOBALS['F_XPATH'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_XPATH'];	 } 
		else if(isset($GLOBALS['F_LDAP'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_LDAP'];	 }
		else if(isset($GLOBALS['F_CONNECT'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_CONNECT'];  }		
		else if(isset($GLOBALS['F_OTHER'][$func_name])) 
		{	$vulnname = 'Possible Flow Control';  } // :X				
		else 
			$vulnname = "Call triggers vulnerability in $func_name().";
		return $vulnname;	
	}
	function getVulnNodeTitle($func_name)
	{
		if(isset($GLOBALS['F_XSS'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_XSS'];  }	
		else if(isset($GLOBALS['F_DATABASE'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_DATABASE'];  }	
		else if(isset($GLOBALS['F_FILE_READ'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_FILE_READ'];  }
		else if(isset($GLOBALS['F_FILE_AFFECT'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_FILE_AFFECT']; }		
		else if(isset($GLOBALS['F_FILE_INCLUDE'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_FILE_INCLUDE'];  }	 		
		else if(isset($GLOBALS['F_EXEC'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_EXEC'];  }
		else if(isset($GLOBALS['F_CODE'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_CODE']; }
		else if(isset($GLOBALS['F_XPATH'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_XPATH'];	 } 
		else if(isset($GLOBALS['F_LDAP'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_LDAP'];}
		else if(isset($GLOBALS['F_CONNECT'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_CONNECT']; }	
		else if(isset($GLOBALS['F_POP'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_POP'];  }
		else if(isset($GLOBALS['F_OTHER'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_OTHER']; } // :X			 			
		else 
			$vulnname = "unknown";
		return $vulnname;	
	}
	// detect vulnerability type given by the PVF name
	// note: same names are used in help.php!
	function increaseVulnCounter($func_name)
	{
		if(isset($GLOBALS['F_XSS'][$func_name])) 
		{	$GLOBALS['count_xss']++; }	
		else if(isset($GLOBALS['F_DATABASE'][$func_name])) 
		{	$GLOBALS['count_sqli']++; }	
		else if(isset($GLOBALS['F_FILE_READ'][$func_name])) 
		{	$GLOBALS['count_fr']++; }
		else if(isset($GLOBALS['F_FILE_AFFECT'][$func_name])) 
		{	$GLOBALS['count_fa']++; }		
		else if(isset($GLOBALS['F_FILE_INCLUDE'][$func_name])) 
		{	$GLOBALS['count_fi']++; }	 		
		else if(isset($GLOBALS['F_EXEC'][$func_name])) 
		{	$GLOBALS['count_exec']++; }
		else if(isset($GLOBALS['F_CODE'][$func_name])) 
		{	$GLOBALS['count_code']++; }
		else if(isset($GLOBALS['F_XPATH'][$func_name])) 
		{	$GLOBALS['count_xpath']++; } 
		else if(isset($GLOBALS['F_LDAP'][$func_name])) 
		{	$GLOBALS['count_ldap']++; }
		else if(isset($GLOBALS['F_CONNECT'][$func_name])) 
		{	$GLOBALS['count_con']++; }	
		else if(isset($GLOBALS['F_POP'][$func_name])) 
		{	$GLOBALS['count_pop']++; }
		else if(isset($GLOBALS['F_OTHER'][$func_name])) 
		{	$GLOBALS['count_other']++; } // :X
	}	
	
	// traced parameter output bottom-up
	function traverseBottomUp($tree) 
	{
		
		switch($tree->marker) 
		{
			case 1:  echo ' USERI '; break;
			case 2:  echo ' VALID '; break;
			case 3:  echo ' FUNCI '; break;
			case 4:  echo ' PERSI '; break;
			default: echo '       '; break;
		}
		echo "\t" . $tree->value;

		if (is_array($tree-children)) {
			foreach ($tree->children as $child) 
			{
				traverseBottomUp($child);
			}
		}
		
		echo "\n";
	}
	
	// traced parameter output top-down
	function traverseTopDown($tree, $start=true, $lines=array()) 
	{
		if($start) echo " ";
	
		if (is_array($tree->children)) {
			foreach ($tree->children as $child) 
			{
				$lines = traverseTopDown($child, false, $lines);
			}
		}
		// do not display a line twice
		// problem: different lines in different files with equal line number
		if(!isset($lines[$tree->line]))
		{
			echo ' ';
			switch($tree->marker) 
			{
				case 1:  echo ' USERI '; break;
				case 2:  echo ' VALID '; break;
				case 3:  echo ' FUNCI '; break;
				case 4:  echo ' PERSI '; break;
				default: echo '       '; break;
			}
			echo "\t",$tree->value,"\n";
			// add to array to ignore next time
			$lines[$tree->line] = 1;
		}	
			
		if($start) echo '';
		
		return $lines;
	}	

	// requirements output
	function dependenciesTraverse($tree) 
	{
		if(!empty($tree->dependencies))
		{
			echo ' ** REQUIRES: ' ."\n";

			foreach ($tree->dependencies as $linenr=>$dependency) 
			{
				if(!empty($dependency))
				{
					// function declaration in requirement is a bit tricky, extract name to form a link
					if( strpos($dependency, 'function ') !== false && ($end=strpos($dependency, '(')) > 10 ) 
						echo ' + '.makefunclink($dependency, $linenr, trim(substr($dependency,9,$end-9)))."\n";
					else
						echo ' + '.highlightline($dependency, $linenr)."\n";
				}
			}

			echo ' **',"\n";
		}
	}
	
	// clean the scanresult
	function cleanoutput($output)
	{
		do
		{
			// remove vulnerable function declaration with no calls
			for($i=count($output[key($output)])-1; $i>=0; $i--)
			{		
				$func_depend = $output[key($output)][$i]->funcdepend;
				if( $func_depend 
				&& !isset($GLOBALS['user_functions'][key($output)][$func_depend]['called']))
				{	
					// delete tree
					$value = $output[key($output)][$i]->name;
					decreaseVulnCounter($value);
					if(count($output[key($output)]) <= 1)
						unset($output[key($output)]);
					else
						unset($output[key($output)][$i]);
						
					if( isset($GLOBALS['user_functions'][key($output)][$value]) )
						unset($GLOBALS['user_functions'][key($output)][$value]);	
				}
			}
		}	
		while(next($output));
		
		// if no more vulnerabilities in file exists delete whole file from output
		foreach($output as $name => $tree)
		{
			if(empty($tree))
				unset($output[$name]);
		}
		return $output;
	}
	
	// check for vulns found in file
	function fileHasVulns($blocks)
	{
		foreach($blocks as $block)
		{
			if($block->vuln)
				return true;
		}
		return false;
	}	
		
	// print the scanresult
	function printoutput($output, $CFG)
	{
		$treestyle = 1;
		if (isset($CFG['treestyle']) && 2 == $CFG['treestyle']) {
			$treestyle = 2;
		} 
		
		$outverb = 2;
		if (isset($CFG['outv7y']) && (1 == $CFG['outv7y'] || 3 == $CFG['outv7y'])) {
			$outverb = $CFG['outv7y'];
		}

		if(!empty($output))
		{
			if ($outverb > 1) {
				do
				{				
					if(key($output) != "" && !empty($output[key($output)]) && fileHasVulns($output[key($output)]))
					{		
						if ($outverb > 2) echo "\n\n";		
						if ($outverb > 2) echo '********************************************************************************************** ', "\n";
						echo "File: " . key($output) . "\n";
						if ($outverb > 2) echo '********************************************************************************************** ', "\n";
						
						if ($outverb > 2) {
							foreach($output[key($output)] as $tree)
							{		
								// print_r($tree); exit;
								
								// if(!empty($tree->get) || !empty($tree->post) 
								// || !empty($tree->cookie) || !empty($tree->files)
								// || !empty($tree->server) )
								// {
								// help & exploit code 
								// }
								
								// $tree->title
								// printf("\n +++ %-25s +++++++++++++++++++++++++++++++++++++++++++++++++++++\n", $tree->category);
								echo "\n +++ ". $tree->category . "\n";
								//echo     '     ',key($output),':',$tree->lines[0],"\n";
								echo     '     ' . $tree->treenodes[0]->value . "\n";
		
								if ($outverb > 3) {
									if($treestyle == 1)
										traverseBottomUp($tree);
									else if($treestyle == 2)
										traverseTopDown($tree);
		
									echo "\n";
									dependenciesTraverse($tree);
									echo "\n";
								}
							}
						}
					}	
					else if(count($output) == 1)
					{
						echo "\n\n",'Nothing vulnerable found. Change the verbosity level or vulnerability type  and try again.',"\n";
					}
				}
				while(next($output));
			}
		}
		else if(count($GLOBALS['scanned_files']) > 0)
		{
			echo "\n\n",'Nothing vulnerable found. Change the verbosity level or vulnerability type and try again (B).',"\n";
		}
		else
		{
			echo "\n\n",' ** Nothing to scan. Please check your path/file name.', "\n";
		}
		
	}
	
	// build list of available functions
	function createFunctionList($user_functions_offset)
	{
		if(!empty($user_functions_offset))
		{
			ksort($user_functions_offset);
			//echo 'declaration;(calls, ...)', "\n";
			foreach($user_functions_offset as $func_name => $info)
			{
				echo $func_name,';(';
								
				$calls = array();
				if(isset($info[3])) {
					foreach($info[3] as $call)
					{
						$calls[] = $call[1];
					}
				}
				echo implode(',',array_unique($calls)).")\n";
			}
			echo "\n";
		}
	}
	
	// build list of all entry points (user input)
	function createUserinputList($user_input)
	{
		if(!empty($user_input))
		{
			ksort($user_input);
			//echo " ** INPUTS: \n type[parameter] \n";
			foreach($user_input as $input_name => $file)
			{
				$finds = array();
				foreach($file as $file_name => $lines)
				{
					foreach($lines as $line)
					{
						$finds[] = "\t$line";
					}
				}
				//echo " ++ $input_name\t",implode(',',array_unique($finds)),"\n";

			}
			//echo "\n\n";
		}
	}
	
	// build list of all scanned files
	function createFileList($files)
	{
		if(!empty($files))
		{
			ksort($files);
			echo "\n";
			foreach($files as $file => $includes)
			{
				if(empty($includes))
					echo ' *   ',$file,"\n";
				else
				{
					echo '  I ',$file,"\n";
					foreach($includes as $include)
					{
						echo '   i ',$include,"\n";
					}
					echo "\n";
				}	

			}
			echo "\n";
		}
	}
	
	function statsRow($nr, $name, $amount, $all)
	{
		// $nr is not used in CLI context, but keeping the calling convention the same
		printf("   %25s   %5d of %d (%.1f%%)\n", $name, $amount, $all, round(($amount/$all)*100,0));
		//echo "\t",$name,"\t",$amount,"\n";
	}
	