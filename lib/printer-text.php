<?php
/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannes.dahse@rub.de)
			
			
Copyright (C) 2012 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.	

**/	
	
	require_once("output_common.php");
	
	// add parsing error to output
	function addError($message, $tokens, $line_nr, $filename)
	{
		$GLOBALS['info'][] = '<font color="red">Parsing error occured. Use verbosity level=debug for details.</font>';
		if($GLOBALS['verbosity'] == 5)
		{
			$value = highlightline($tokens, '', $line_nr);
			$new_find = new InfoTreeNode($value);
			$new_find->title = 'Parse error: '.$message;
			$new_find->lines[] = $line_nr;
			$new_find->filename = $filename;
								
			$new_block = new VulnBlock('error', 'Debug');
			$new_block->treenodes[] = $new_find;
			$new_block->vuln = true;
			$GLOBALS['output'][$filename]['error'] = $new_block;
		}	
	}
	

	// prepare output to style with CSS
	function highlightline($tokens=array(), $comment='', $line_nr, $title=false, $udftitle=false, $tainted_vars=array())
	{
		$reference = true;
		$output = "$line_nr : ";
		if($title)
		{
			$output.= $title;
		} 
		else if($udftitle)
		{
			$output.= " UDF: $udftitle ";
		}
		
		$var_count = 0;
		
		for($i=0;$i<count($tokens);$i++)
		{
			$token = $tokens[$i];
			if (is_string($token))
			{		
				if($token === ',' || $token === ';')
					$output .= "$token ";
				else if(in_array($token, Tokens::$S_SPACE_WRAP) || in_array($token, Tokens::$S_ARITHMETIC))
					$output .= "$token ";
				else
					$output .= htmlentities($token, ENT_QUOTES, 'utf-8');
					
			} 
			else if (is_array($token) 
			&& $token[0] !== T_OPEN_TAG
			&& $token[0] !== T_CLOSE_TAG) 
			{
				
				if(in_array($token[0], Tokens::$T_SPACE_WRAP) || in_array($token[0], Tokens::$T_OPERATOR) || in_array($token[0], Tokens::$T_ASSIGNMENT))
				{
					$output.= " $token[1] ";
				}	
				else
				{
					if($token[0] === T_FUNCTION)
					{
						$reference = false;
						$funcname = $tokens[$i+1][0] === T_STRING ? $tokens[$i+1][1] : $tokens[$i+2][1];
						//$output .= '<A NAME="'.$funcname.'_declare" class="jumplink"></A>';
						//$output .= '<a class="link" style="text-decoration:none;" href="#'.$funcname.'_call" title="jump to call">&dArr;</a>&nbsp;';
					}	
					
					$text = htmlentities($token[1], ENT_QUOTES, 'utf-8');
					$text = str_replace(array(' ', "\n"), '&nbsp;', $text);

					if($token[0] === T_FUNCTION)
						$text.=' ';
						
					if($token[0] === T_STRING && $reference 
					&& isset($GLOBALS['user_functions_offset'][strtolower($text)]))
					{				
						//$text = @'<span onmouseover="getFuncCode(this,\''.addslashes($GLOBALS['user_functions_offset'][strtolower($text)][0]).'\',\''.$GLOBALS['user_functions_offset'][strtolower($text)][1].'\',\''.$GLOBALS['user_functions_offset'][strtolower($text)][2].'\')" style="text-decoration:underline" class="phps-'.str_replace('_', '-', strtolower(token_name($token[0])))."\">$text</span>\n";
					}	
					else 
					{
						//$span = '<span ';
					
						//if($token[0] === T_VARIABLE)
						//{
						//	$var_count++;
						//	$cssname = str_replace('$', '', $token[1]);
						//	$span.= 'style="cursor:pointer;" name="phps-var-'.$cssname.'" onClick="markVariable(\''.$cssname.'\')" ';
						//	$span.= 'onmouseover="markVariable(\''.$cssname.'\')" onmouseout="markVariable(\''.$cssname.'\')" ';
						//}	
						
						if($token[0] === T_VARIABLE && @in_array($var_count, $tainted_vars))
							$span.= " $text ";	
						else
							$span.= " $text ";
							
						$text = $span;	
						
						// rebuild array keys
						if(isset($token[3]))
						{
							foreach($token[3] as $key)
							{
								if($key != '*')
								{
									$text .= "\n  ";
									if(!is_array($key))
									{
										if(is_numeric($key))
											$text .= $key . ' ';
										else
											$text .= " '" . htmlentities($key, ENT_QUOTES, 'utf-8') . "' ";
									} else
									{
										foreach($key as $token)
										{
											if(is_array($token))
											{
												
												
												//if($token[0] === T_VARIABLE)
												//{
													//$cssname = str_replace('$', '', $token[1]);
													//$text.= 'style="cursor:pointer;" name="phps-var-'.$cssname.'" onClick="markVariable(\''.$cssname.'\')" ';
													//$text.= 'onmouseover="markVariable(\''.$cssname.'\')" onmouseout="markVariable(\''.$cssname.'\')" ';
												//}	
												
												$text .= htmlentities($token[1], ENT_QUOTES, 'utf-8').' ';
											}	
											else
												$text .= "$token ";
										}
									}
									//$text .= '<span class="phps-code">]</span>';
								}
							}
						}
					}
					$output .= $text;
					if(is_array($token) && (in_array($token[0], Tokens::$T_INCLUDES) || in_array($token[0], Tokens::$T_XSS) || $token[0] === 'T_EVAL'))
						$output .= ' ';
				}		
			}
		}
		
		if(!empty($comment))
			$output .= ' // '.htmlentities($comment, ENT_QUOTES, 'utf-8')."\n";

		return $output;
	}
	

		
	// traced parameter output bottom-up
	function traverseBottomUp($tree) 
	{
		echo '<ul';
		switch($tree->marker) 
		{
			case 1: echo ' class="userinput"'; break;
			case 2: echo ' class="validated"'; break;
			case 3: echo ' class="functioninput"'; break;
			case 4: echo ' class="persistent"'; break;
		}
		echo '><li>' . $tree->value;

		if($tree->children)
		{
			foreach ($tree->children as $child) 
			{
				traverseBottomUp($child);
			}
		}
		echo '</li></ul>',"\n";
	}
	
	// traced parameter output top-down
	function traverseTopDown($tree, $start=true, $lines=array()) 
	{
		if($start) echo '<ul>';
	
		foreach ($tree->children as $child) 
		{
			$lines = traverseTopDown($child, false, $lines);
		}
		
		// do not display a line twice
		// problem: different lines in different files with equal line number
		if(!isset($lines[$tree->line]))
		{
			echo '<li';
			switch($tree->marker) 
			{
				case 1: echo ' class="userinput"'; break;
				case 2: echo ' class="validated"'; break;
				case 3: echo ' class="functioninput"'; break;
				case 4: echo ' class="persistent"'; break;
			}
			echo '>',$tree->value,'</li>',"\n";
			// add to array to ignore next time
			$lines[$tree->line] = 1;
		}	
			
		if($start) echo '</ul>';
		
		return $lines;
	}	

	// requirements output
	function dependenciesTraverse($tree) 
	{
		if(!empty($tree->dependencies))
		{
			echo '<ul><li><span class="requires">requires:</span>';

			foreach ($tree->dependencies as $linenr=>$dependency) 
			{
				if(!empty($dependency))
				{
					echo '<ul><li>'.highlightline($dependency, '', $linenr).'</li></ul>';
				}
			}

			echo '</li></ul>',"\n";
		}
	}
	
	
	
	// print the scanresult
	function printoutput($output, $treestyle=1)
	{
		if(!empty($output))
		{
			$nr=0;
			reset($output);
			do
			{				
				if(key($output) != "" && !empty($output[key($output)]) && fileHasVulns($output[key($output)]))
				{		
					echo '<div class="filebox">',
					'<span class="filename">File: ',key($output),'</span><br>',
					'<div id="',key($output),'"><br>';
	
					foreach($output[key($output)] as $vulnBlock)
					{	
						if($vulnBlock->vuln)	
						{
							$nr++;
							echo '<div class="vulnblock">',
							'<div id="pic',$vulnBlock->category,$nr,'" class="minusico" name="pic',$vulnBlock->category,'" style="margin-top:5px" title="minimize"',
							' onClick="hide(\'',$vulnBlock->category,$nr,'\')"></div><div class="vulnblocktitle">',$vulnBlock->category,'</div>',
							'</div><div name="allcats"><div class="vulnblock" style="border-top:0px" name="',$vulnBlock->category,'" id="',$vulnBlock->category,$nr,'">';
							
							if($treestyle == 2)
								krsort($vulnBlock->treenodes);
							
							foreach($vulnBlock->treenodes as $tree)
							{
								// we do not have a prescan yet so RIPS misses function calls before the actual declaration, so we output vulns in functions without function call too (could have happened earlier)
								// if(empty($tree->funcdepend) || $tree->foundcallee )
								{	
									echo '<div class="codebox"><table border=0>',"\n",
									'<tr><td valign="top" nowrap>',"\n",
									'<div class="fileico" title="review code" ',
									'onClick="openCodeViewer(this,\'',
									addslashes($tree->filename), '\',\'',
									implode(',', $tree->lines), '\');"></div>'."\n",
									'<div id="pic',key($output),$tree->lines[0],'" class="minusico" title="minimize"',
									' onClick="hide(\'',addslashes(key($output)),$tree->lines[0],'\')"></div><br />',"\n";

									if(isset($GLOBALS['scan_functions'][$tree->name]))
									{
										// help button
										echo '<div class="help" title="get help" onClick="openHelp(this,\'',
										$vulnBlock->category,'\',\'',$tree->name,'\',\'',
										(int)!empty($tree->get),'\',\'',
										(int)!empty($tree->post),'\',\'',
										(int)!empty($tree->cookie),'\',\'',
										(int)!empty($tree->files),'\',\'',
										(int)!empty($tree->cookie),'\')"></div>',"\n";
										
										if(isset($GLOBALS['F_DATABASE'][$tree->name])
										|| isset($GLOBALS['F_FILE_AFFECT'][$tree->name]) 
										|| isset($GLOBALS['F_FILE_READ'][$tree->name]) 
										|| isset($GLOBALS['F_LDAP'][$tree->name])
										|| isset($GLOBALS['F_XPATH'][$tree->name])
										|| isset($GLOBALS['F_POP'][$tree->name]) )
										{
											// data leak scan
											if(!empty($vulnBlock->dataleakvar))
											{
												echo '<div class="dataleak" title="check data leak" onClick="leakScan(this,\'',
												$vulnBlock->dataleakvar[1],'\',\'', // varname
												$vulnBlock->dataleakvar[0],'\', false)"></div>',"\n"; // line
											} else
											{
												$tree->title .= ' (Blind exploitation)';
											}
										}	
									}
									
									if(!empty($tree->get) || !empty($tree->post) 
									|| !empty($tree->cookie) || !empty($tree->files)
									|| !empty($tree->server) )
									{
										/*echo '<div class="hotpatch" title="hotpatch" ',
										'onClick="openHotpatch(this, \'',
										addslashes($tree->filename),
										'\',\'',implode(',',array_unique($tree->get)),
										'\',\'',implode(',',array_unique($tree->post)),
										'\',\'',implode(',',array_unique($tree->cookie)),
										'\',\'',implode(',',array_unique($tree->files)),
										'\',\'',implode(',',array_unique($tree->server)),'\');"></div>',"\n",*/
										
										echo '<div class="exploit" title="generate exploit" ',
										'onClick="openExploitCreator(this, \'',
										addslashes($tree->filename),
										'\',\'',implode(',',array_unique($tree->get)),
										'\',\'',implode(',',array_unique($tree->post)),
										'\',\'',implode(',',array_unique($tree->cookie)),
										'\',\'',implode(',',array_unique($tree->files)),
										'\',\'',implode(',',array_unique($tree->server)),'\');"></div>';
									}
									// $tree->title
									echo '</td><td><span class="vulntitle">',$tree->title,'</span>',
									'<div class="code" id="',key($output),$tree->lines[0],'">',"\n";

									if($treestyle == 1)
										traverseBottomUp($tree);
									else if($treestyle == 2)
										traverseTopDown($tree);

										echo '<ul><li>',"\n";
									dependenciesTraverse($tree);
									echo '</li></ul>',"\n",	'</div>',"\n", '</td></tr></table></div>',"\n";
								}
							}	
							
							if(!empty($vulnBlock->alternatives))
							{
								echo '<div class="codebox"><table><tr><td><ul><li><span class="vulntitle">Vulnerability is also triggered in:</span>';
								foreach($vulnBlock->alternatives as $alternative)
								{
									echo '<ul><li>'.$alternative.'</li></ul>';
								}
								echo '</li></ul></td></table></div>';
							}
							
							echo '</div></div><div style="height:20px"></div>',"\n";
						}	
					}

					echo '</div><div class="buttonbox">',"\n",
					'<input type="submit" class="Button" value="hide all" ',
					'onClick="hide(\'',addslashes(key($output)),'\')">',"\n",
					'</div></div><hr>',"\n";
				}	
				else if(count($output) == 1)
				{
					echo '<div style="margin-left:30px;color:#000000">Nothing vulnerable found. Change the verbosity level or vulnerability type  and try again.</div>';
				}
			}
			while(next($output));
		}
		else if(count($GLOBALS['scanned_files']) > 0)
		{
			echo '<div style="margin-left:30px;color:#000000">Nothing vulnerable found. Change the verbosity level or vulnerability type and try again.</div>';
		}
		else
		{
			echo '<div style="margin-left:30px;color:#000000">Nothing to scan. Please check your path/file name.</div>';
		}
		
	}
	
	// build list of available functions
	function createFunctionList($user_functions_offset)
	{
		if(!empty($user_functions_offset))
		{
			ksort($user_functions_offset);
			if($GLOBALS['file_amount'] <= WARNFILES)
				$js = 'graph2 = new Graph(document.getElementById("functioncanvas"));'."\n";
			else
				$js = 'canvas = document.getElementById("functioncanvas");ctx = canvas.getContext("2d");ctx.fillStyle="#ff0000";ctx.fillText("Graphs have been disabled for a high file amount (>'.WARNFILES.').", 20, 30);';
			$x=20;
			$y=50;
			$i=0;
			
			if($GLOBALS['file_amount'] <= WARNFILES)
			{
				// create JS graph elements
				foreach($user_functions_offset as $func_name => $info)
				{				
					if($func_name !== '__main__')
					{
						$x = ($i%4==0) ? $x=20 : $x=$x+160;
						$y = ($i%4==0) ? $y=$y+70 : $y=$y;
						$i++;
						
						$func_varname = str_replace('::', '', $func_name);
						
						$js.= "var e$func_varname = graph2.addElement(pageTemplate, { x:$x, y:$y }, '".addslashes($func_name)."( )', '', '".(isset($info[5]) ? $info[5] : 0)."', '".(isset($info[6]) ? $info[6] : 0)."', 0);\n";
					} else
					{	
						$js.='var e__main__ = graph2.addElement(pageTemplate, { x:260, y:20 }, "__main__", "", "'.(isset($info[5]) ? $info[5] : 0).'", "'.(isset($info[6]) ? $info[6] : 0).'", 0);'."\n";
					}	
				}
			}
			
			echo '<div id="functionlistdiv"><table><tr><th align="left">declaration</th><th align="left">calls</th></tr>';
			foreach($user_functions_offset as $func_name => $info)
			{
				if($func_name !== '__main__')
				echo '<tr><td><div id="fol_',$func_name,'" class="funclistline" title="',$info[0],'" ',
				'onClick="openCodeViewer(3, \'',addslashes($info[0]),'\', \'',($info[1]+1),
				',',(!empty($info[2]) ? $info[2]+1 : 0),'\')">',$func_name,'</div></td><td>';
								
				$calls = array();
				if(isset($info[3]))
				{
					foreach($info[3] as $call)
					{
						$calls[] = '<span class="funclistline" title="'.$call[0].
						'" onClick="openCodeViewer(3, \''.addslashes($call[0]).'\', \''.$call[1].'\')">'.$call[1].'</span>';
					}
				}
				echo implode(',',array_unique($calls)).'</td></tr>';
				
				if(isset($info[4]) && $GLOBALS['file_amount'] <= WARNFILES)
				{
					foreach($info[4] as $call)
					{
						if(!is_array($call))
						{
							$color = (isset($info[4][$call])) ? '#F00' : '#000';
							$js.="try{graph2.addConnection(e$call.getConnector(\"links\"), e$func_name.getConnector(\"parents\"), '$color');}catch(e){}\n";
						}	
					}
				}
			}
			if($GLOBALS['file_amount'] <= WARNFILES)
				$js.='graph2.update();';
			echo '</table></div>',"\n<div id='functiongraph_code' style='display:none'>$js</div>\n";
		} else
		{
			echo "<div id='functiongraph_code' style='display:none'>document.getElementById('windowcontent3').innerHTML='No user defined functions found.'</div>\n";
		}
	}
	
	// build list of all entry points (user input)
	function createUserinputList($user_input)
	{
		if(!empty($user_input))
		{
			ksort($user_input);
			echo '<table><tr><th align="left">type[parameter]</th><th align="left">taints</th></tr>';
			foreach($user_input as $input_name => $file)
			{
				$finds = array();
				foreach($file as $file_name => $lines)
				{
					foreach($lines as $line)
					{
						$finds[] = '<span class="funclistline" title="'.$file_name.'" onClick="openCodeViewer(4, \''.addslashes($file_name)."', '$line')\">$line</span>\n";
					}
				}
				echo "<tr><td nowrap>$input_name</td><td nowrap>",implode(',',array_unique($finds)),'</td></tr>';

			}
			echo '</table>';
		} else
		{
			echo 'No userinput found.';
		}
	}
	
	// build list of all scanned files
	function createFileList($files, $file_sinks)
	{
		if(!empty($files))
		{
			if($GLOBALS['file_amount'] <= WARNFILES)
				$js = 'graph = new Graph(document.getElementById("filecanvas"));'."\n";
			else	
				$js = 'canvas = document.getElementById("filecanvas");ctx = canvas.getContext("2d");ctx.fillStyle="#ff0000";ctx.fillText("Graphs have been disabled for a high file amount (>'.WARNFILES.').", 20, 30);';
	
			// get vuln files
			$vulnfiles = array();
			foreach($GLOBALS['output'] as $filename => $blocks)
			{		
				foreach($blocks as $block)
				{
					if($block->vuln)
					{
						$vulnfiles[] = $block->treenodes[0]->filename;
					}	
				}	
			}	

			// sort files by "include weight" (main files on top, included files bottom)
			$mainfiles = array();
			$incfiles = array();
			foreach($files as $file => $includes)
			{
				$mainfiles[] = realpath($file);
				if(!empty($includes))
				{
					foreach($includes as $include)
					{
						$incfiles[] = realpath($include);
					}
				}	
			}
			$elements = array_unique(array_merge(array_diff($mainfiles,$incfiles), array('__break__'), $incfiles));
			$x=20;
			$y=-50;
			$i=0;
			$style = 'pageTemplate';

			// add JS elements
			foreach($elements as $file)
			{
				if($file !== '__break__')
				{
					$x = ($i%4==0) ? $x=20 : $x=$x+160;
					$y = ($i%4==0) ? $y=$y+70 : $y=$y;
					$i++;
					
					// leave space for legend symbols
					if($i==3)
						$i++;
					
					$file = realpath($file);

					$filename = is_dir($CONFIG['loc']) ? str_replace(realpath($CONFIG['loc']), '', $file) : str_replace(realpath(str_replace(basename($CONFIG['loc']),'', $CONFIG['loc'])),'',$file);
					$varname = preg_replace('/[^A-Za-z0-9]/', '', $filename); 

					$userinput = 0;
					foreach($GLOBALS['user_input'] as $inputname)
					{
						if(isset($inputname[$file]))
							$userinput++;
					}			
					
					if($GLOBALS['file_amount'] <= WARNFILES)
						$js.= "var e$varname = graph.addElement($style, { x:$x, y:$y }, '".addslashes($filename)."', '', '".$userinput."', '".$file_sinks[$file]."', ".(in_array($file, $vulnfiles) ? 1 : 0).");\n";

				} else
				{
					// add to $i what is missing til new row is created
					$i=$i+(4-($i%4));
					$y+=30;
					$style = 'scriptTemplate';
				}
			}	
			
			// build file list and add connection to includes
			//echo "*** FILE LIST ***\n";
			foreach($files as $file => $includes)
			{				
				$file = realpath($file);

				$filename = is_dir($CONFIG['loc']) ? str_replace(realpath($CONFIG['loc']), '', $file) : str_replace(realpath(str_replace(basename($CONFIG['loc']),'', $CONFIG['loc'])),'',$file);
				$varname = preg_replace('/[^A-Za-z0-9]/', '', $filename); 

				if(empty($includes))
				{
					echo "\t",$file,"\n";
				}	
				else
				{
					$parent = $varname;
					echo "\t",$file,"\n";
					foreach($includes as $include)
					{
						$include = realpath($include);
	
						$includename = is_dir($CONFIG['loc']) ? str_replace(realpath($CONFIG['loc']), '', $include) : str_replace(realpath(str_replace(basename($CONFIG['loc']),'', $CONFIG['loc'])),'',$include);
						$incvarname = preg_replace('/[^A-Za-z0-9]/', '', $includename); 
	
						echo "\t\t",$includename,"\n";
						
						//if($GLOBALS['file_amount'] <= WARNFILES)
							//$js.="try{graph.addConnection(e$incvarname.getConnector(\"links\"), e$parent.getConnector(\"parents\"), '#000');}catch(e){}\n";
					}
					//echo '</ul></td></tr>',"\n";
				}	

			}
			if($GLOBALS['file_amount'] <= WARNFILES)
				$js.='graph.update();';
			//echo '</table></div>',"\n<div id='filegraph_code' style='display:none'>$js</div>\n";
		}
	}
	
	function statsRow($nr, $name, $amount, $all)
	{
		printf("   %25s   %5d of %d (%.1f%%)\n", $name, $amount, $all, round(($amount/$all)*100,0));
	}
	
	function showPage() 
	{
		global $CONFIG, $output, $info, $count_inc,$count_inc_fail,$elapsed, $files;
		global $count_xss,$count_sqli,$count_fr,$count_fa,$count_fi,$count_exec,$count_code,$count_eval;
		global $count_xpath,$count_ldap,$count_con,$count_other,$count_pop,$count_header;
		global $scanned_files,$scan_functions,$user_functions_offset,$user_input,$file_sinks_count;
		global $NAME_CODE,$NAME_EXEC,$NAME_CONNECT,$NAME_FILE_READ,$NAME_FILE_INCLUDE,$NAME_FILE_AFFECT;
		global $NAME_LDAP,$NAME_DATABASE,$NAME_XPATH,$NAME_XSS,$NAME_HTTP_HEADER,$NAME_OTHER,$NAME_POP;

		if ('cli' != PHP_SAPI) {		
			echo "<pre>\n";
		}

		
		echo "\n", '=================== RESULTS SUMMARY ====================', "\n";

		if(empty($CONFIG['search']))
		{
			$count_all=$count_xss+$count_sqli+$count_fr+$count_fa+$count_fi+$count_exec+$count_code+$count_eval+$count_xpath+$count_ldap+$count_con+$count_other+$count_pop+$count_header;
			if($count_all > 0)
			{
				if($count_code > 0)
					statsRow(1, $NAME_CODE, $count_code, $count_all);
				if($count_exec > 0)	
					statsRow(2, $NAME_EXEC, $count_exec, $count_all);
				if($count_con > 0)	
					statsRow(3, $NAME_CONNECT, $count_con, $count_all);
				if($count_fr > 0)	
					statsRow(4, $NAME_FILE_READ, $count_fr, $count_all);
				if($count_fi > 0)	
					statsRow(5, $NAME_FILE_INCLUDE, $count_fi, $count_all);
				if($count_fa > 0)	
					statsRow(6, $NAME_FILE_AFFECT, $count_fa, $count_all);
				if($count_ldap > 0)	
					statsRow(7, $NAME_LDAP, $count_ldap, $count_all);
				if($count_sqli > 0)	
					statsRow(8, $NAME_DATABASE, $count_sqli, $count_all);
				if($count_xpath > 0)	
					statsRow(9, $NAME_XPATH, $count_xpath, $count_all);
				if($count_xss > 0)	
					statsRow(10, $NAME_XSS, $count_xss, $count_all);
				if($count_header > 0)	
					statsRow(11, $NAME_HTTP_HEADER, $count_header, $count_all);	
				if($count_other > 0)	
					statsRow(12, $NAME_OTHER, $count_other, $count_all);
				if($count_pop > 0)	
					statsRow(13, $NAME_POP, $count_pop, $count_all);	
					
				//echo "\n\t\tSum:\t",$count_all,"\n"; 
				printf("   %25s   %5d\n", 'TOTAL', $count_all);
				//printf("   %25s   %5d\n", 'Scan Functions', count($scan_functions));
			} else
			{
				echo "\nNo vulnerabilities found.\n";
			}
		} else {
			echo "\n Search support not completed \n\n";
		}
		echo '========================================================', "\n\n";

		if(empty($CONFIG['search']))
		{
			
			if($count_inc > 0)
			{
				$is = ($count_inc_success=$count_inc-$count_inc_fail).'/'.$count_inc . 
				' ('.round(($count_inc_success/$count_inc)*100,0).'%)'; 
			} else
			{
				$is = " No includes.";
			}
			echo "\nScanned Files:            " , count($scanned_files);
			echo "\nInclude success:          " , $is;
			echo "\nConsidered sinks:         " , count($scan_functions);
			echo "\nUser-defined functions: * " , (count($user_functions_offset)-(count($user_functions_offset)>0?1:0));
			echo "\nUnique sources:           " , count($user_input);
			echo "\nSensitive sinks:        * " , (is_array($file_sinks_count) ? array_sum($file_sinks_count) : 0);
			echo "\n";
			
			// output info gathering
			if(!empty($info))
			{
				$info = array_unique($info);
				foreach($info as $detail)
				{
					echo "\nInfo:                   $detail";
				}	
			}
			
			echo "\n\n";
	
		}
			
		//printoutput($output, $CONFIG);
		
		if ($CONFIG['outv7y'] > 2) {
			echo "\n============== INCLUDE TREE ===============================\n";
			createFileList($scanned_files);		
			echo "\n===========================================================\n";
		}

		if ($CONFIG['outv7y'] > 3) {
			echo "\n============== FUNCTION LIST ==============================\n";
			createFunctionList($user_functions_offset);
		}		
		
		if ($CONFIG['outv7y'] > 3) {
			echo "\n============== USER INPUT LIST ============================\n";
			createUserinputList($user_input);		
		}
		
		
		//@printoutput($output, $CONFIG); 
		
		echo "\n============== ELAPSED TIME ===============================\n";		
		printf("Scanned %d files in %.03f seconds", count($scanned_files), $elapsed);
		echo "\n===========================================================\n";
		
		if ('cli' != PHP_SAPI) 
		{
			echo "<pre>\n";
		} 
	}
