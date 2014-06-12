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
		$output = "<span class=\"linenr\">$line_nr:</span>&nbsp;";
		if($title)
		{
			$output.='<a class="link" href="'.PHPDOC.$title.'" title="open php documentation" target=_blank>';
			$output.="$title</a>&nbsp;";
		} 
		else if($udftitle)
		{
			$output.='<a class="link" style="text-decoration:none;" href="#'.$udftitle.'_declare" title="jump to declaration">&uArr;</a>&nbsp;';
		}
		
		$var_count = 0;
		
		for($i=0;$i<count($tokens);$i++)
		{
			$token = $tokens[$i];
			if (is_string($token))
			{		
				if($token === ',' || $token === ';')
					$output .= "<span class=\"phps-code\">$token&nbsp;</span>";
				else if(in_array($token, Tokens::$S_SPACE_WRAP) || in_array($token, Tokens::$S_ARITHMETIC))
					$output .= '<span class="phps-code">&nbsp;'.$token.'&nbsp;</span>';
				else
					$output .= '<span class="phps-code">'.htmlentities($token, ENT_QUOTES, 'utf-8').'</span>';
					
			} 
			else if (is_array($token) 
			&& $token[0] !== T_OPEN_TAG
			&& $token[0] !== T_CLOSE_TAG) 
			{
				
				if(in_array($token[0], Tokens::$T_SPACE_WRAP) || in_array($token[0], Tokens::$T_OPERATOR) || in_array($token[0], Tokens::$T_ASSIGNMENT))
				{
					$output.= '&nbsp;<span class="phps-'.str_replace('_', '-', strtolower(token_name($token[0])))."\">{$token[1]}</span>&nbsp;";
				}	
				else
				{
					if($token[0] === T_FUNCTION)
					{
						$reference = false;
						$funcname = $tokens[$i+1][0] === T_STRING ? $tokens[$i+1][1] : $tokens[$i+2][1];
						$output .= '<A NAME="'.$funcname.'_declare" class="jumplink"></A>';
						$output .= '<a class="link" style="text-decoration:none;" href="#'.$funcname.'_call" title="jump to call">&dArr;</a>&nbsp;';
					}	
					
					$text = htmlentities($token[1], ENT_QUOTES, 'utf-8');
					$text = str_replace(array(' ', "\n"), '&nbsp;', $text);

					if($token[0] === T_FUNCTION)
						$text.='&nbsp;';
						
					if($token[0] === T_STRING && $reference 
					&& isset($GLOBALS['user_functions_offset'][strtolower($text)]))
					{				
						$text = @'<span onmouseover="getFuncCode(this,\''.addslashes($GLOBALS['user_functions_offset'][strtolower($text)][0]).'\',\''.$GLOBALS['user_functions_offset'][strtolower($text)][1].'\',\''.$GLOBALS['user_functions_offset'][strtolower($text)][2].'\')" style="text-decoration:underline" class="phps-'.str_replace('_', '-', strtolower(token_name($token[0])))."\">$text</span>\n";
					}	
					else 
					{
						$span = '<span ';
					
						if($token[0] === T_VARIABLE)
						{
							$var_count++;
							$cssname = str_replace('$', '', $token[1]);
							$span.= 'style="cursor:pointer;" name="phps-var-'.$cssname.'" onClick="markVariable(\''.$cssname.'\')" ';
							$span.= 'onmouseover="markVariable(\''.$cssname.'\')" onmouseout="markVariable(\''.$cssname.'\')" ';
						}	
						
						if($token[0] === T_VARIABLE && @in_array($var_count, $tainted_vars))
							$span.= "class=\"phps-tainted-var\">$text</span>";	
						else
							$span.= 'class="phps-'.str_replace('_', '-', strtolower(token_name($token[0])))."\">$text</span>";
							
						$text = $span;	
						
						// rebuild array keys
						if(isset($token[3]))
						{
							foreach($token[3] as $key)
							{
								if($key != '*')
								{
									$text .= '<span class="phps-code">[</span>';
									if(!is_array($key))
									{
										if(is_numeric($key))
											$text .= '<span class="phps-t-lnumber">' . $key . '</span>';
										else
											$text .= '<span class="phps-t-constant-encapsed-string">\'' . htmlentities($key, ENT_QUOTES, 'utf-8') . '\'</span>';
									} else
									{
										foreach($key as $token)
										{
											if(is_array($token))
											{
												$text .= '<span ';
												
												if($token[0] === T_VARIABLE)
												{
													$cssname = str_replace('$', '', $token[1]);
													$text.= 'style="cursor:pointer;" name="phps-var-'.$cssname.'" onClick="markVariable(\''.$cssname.'\')" ';
													$text.= 'onmouseover="markVariable(\''.$cssname.'\')" onmouseout="markVariable(\''.$cssname.'\')" ';
												}	
												
												$text .= 'class="phps-'.str_replace('_', '-', strtolower(token_name($token[0]))).'">'.htmlentities($token[1], ENT_QUOTES, 'utf-8').'</span>';
											}	
											else
												$text .= "<span class=\"phps-code\">{$token}</span>";
										}
									}
									$text .= '<span class="phps-code">]</span>';
								}
							}
						}
					}
					$output .= $text;
					if(is_array($token) && (in_array($token[0], Tokens::$T_INCLUDES) || in_array($token[0], Tokens::$T_XSS) || $token[0] === 'T_EVAL'))
						$output .= '&nbsp;';
				}		
			}
		}
		
		if(!empty($comment))
			$output .= '&nbsp;<span class="phps-t-comment">// '.htmlentities($comment, ENT_QUOTES, 'utf-8').'</span>';

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
			echo '<div id="filelistdiv"><table>';
			foreach($files as $file => $includes)
			{				
				$file = realpath($file);

				$filename = is_dir($CONFIG['loc']) ? str_replace(realpath($CONFIG['loc']), '', $file) : str_replace(realpath(str_replace(basename($CONFIG['loc']),'', $CONFIG['loc'])),'',$file);
				$varname = preg_replace('/[^A-Za-z0-9]/', '', $filename); 

				if(empty($includes))
				{
					echo '<tr><td><div class="funclistline" title="',$file,'" ',
					'onClick="openCodeViewer(3, \'',addslashes($file),'\', \'0\')">',$filename,'</div></td></tr>',"\n";
				}	
				else
				{
					$parent = $varname;
					echo '<tr><td><div class="funclistline" title="',$file,'" ',
					'onClick="openCodeViewer(3, \'',addslashes($file),'\', \'0\')">',$filename,'</div><ul style="margin-top:0px;">',"\n";
					foreach($includes as $include)
					{
						$include = realpath($include);
	
						$includename = is_dir($CONFIG['loc']) ? str_replace(realpath($CONFIG['loc']), '', $include) : str_replace(realpath(str_replace(basename($CONFIG['loc']),'', $CONFIG['loc'])),'',$include);
						$incvarname = preg_replace('/[^A-Za-z0-9]/', '', $includename); 
	
						echo '<li><div class="funclistline" title="',$include,'" ',
						'onClick="openCodeViewer(3, \'',addslashes($include),'\', \'0\')">',$includename,'</div></li>',"\n";
						
						if($GLOBALS['file_amount'] <= WARNFILES)
							$js.="try{graph.addConnection(e$incvarname.getConnector(\"links\"), e$parent.getConnector(\"parents\"), '#000');}catch(e){}\n";
					}
					echo '</ul></td></tr>',"\n";
				}	

			}
			if($GLOBALS['file_amount'] <= WARNFILES)
				$js.='graph.update();';
			echo '</table></div>',"\n<div id='filegraph_code' style='display:none'>$js</div>\n";
		}
	}
	
	function statsRow($nr, $name, $amount, $all)
	{
		echo '<tr><td nowrap onmouseover="this.style.color=\'white\';" onmouseout="this.style.color=\'#DFDFDF\';" onClick="catshow(\'',$name,'\')" style="cursor:pointer;" title="show only vulnerabilities of this category">',$name,':</td><td nowrap><div id="chart'.$nr.'" class="chart" style="width:',
			round(($amount/$all)*100,0),'"></div><div id="vuln'.$nr.'">',$amount,'</div></td></tr>';
	}
	

	function showPage()
	{

		global $CONFIG, $output, $info, $count_inc,$count_inc_fail,$elapsed, $files;
		global $count_xss,$count_sqli,$count_fr,$count_fa,$count_fi,$count_exec,$count_code,$count_eval;
		global $count_xpath,$count_ldap,$count_con,$count_other,$count_pop,$count_header;
		global $scanned_files,$scan_functions,$user_functions_offset,$user_input,$file_sinks_count;
		global $NAME_CODE,$NAME_EXEC,$NAME_CONNECT,$NAME_FILE_READ,$NAME_FILE_INCLUDE,$NAME_FILE_AFFECT;
		global $NAME_LDAP,$NAME_DATABASE,$NAME_XPATH,$NAME_XSS,$NAME_HTTP_HEADER,$NAME_OTHER,$NAME_POP;		
		?><div id="window1" name="window" style="width:600px; height:250px;">
	<div class="windowtitlebar">
		<div id="windowtitle1" onClick="top(1)" onmousedown="dragstart(1)" class="windowtitle"></div>
		<input id="maxbutton1" type="button" class="maxbutton" value="&nabla;" onClick="maxWindow(1, 800)" title="maximize" />
		<input type="button" class="closebutton" value="x" onClick="closeWindow(1)" title="close" />
	</div>

	<div style="position:relative;width:100%;">
	<div id="scrolldiv">
		<div id="scrollwindow"></div>
		<div id="scrollcode"></div>
	</div>
	<div id="windowcontent1" class="windowcontent" onscroll="scroller()"></div>
	<div style="clear:left;"></div>
	</div>
	
	<div id="return" class="return" onClick="returnLastCode()">&crarr; return</div>
	<div class="windowfooter" onmousedown="resizeStart(event, 1)"></div>
</div>

<div id="window2" name="window" style="width:600px; height:250px;">
	<div class="windowtitlebar">
		<div id="windowtitle2" onClick="top(2)" onmousedown="dragstart(2)" class="windowtitle"></div>
		<input type="button" class="closebutton" value="x" onClick="closeWindow(2)" title="close" />
	</div>
	<div id="windowcontent2" class="windowcontent"></div>
	<div class="windowfooter" onmousedown="resizeStart(event, 2)"></div>
</div>

<div id="window3" name="window" style="width:300px; height:300px;">
	<div class="funclisttitlebar">
		<div id="windowtitle3" onClick="top(3)" onmousedown="dragstart(3)" class="funclisttitle">
		user defined functions and calls
		</div>
		<input type="button" class="closebutton" value="x" onClick="closeWindow(3)" title="close" />
	</div>
	<div id="windowcontent3" class="funclistcontent">
		<div >
			<input type="button" id="functionlistbutton" class="button" onclick="showlist('function');minWindow(3, 650);" value="list" style="background:white;color:black;" />
			<input type="button" id="functiongraphbutton" class="button" onclick="showgraph('function');maxWindow(3, 650);" value="graph"/>
			<input type="button" id="functioncanvassave" class="button" onclick="saveCanvas('functioncanvas', 3)" value="save graph" />
			<?php
				if ($verbosity == 5)
					echo '<br>(graph not available in debug mode)';
 ?>
		</div>
		<?php
		createFunctionList($user_functions_offset);
		?>
		<div id="canvas3" style="display:none"></div>
		<canvas id="functioncanvas" tabindex="0" width="650" height="<?php echo (count($user_functions_offset)/4)*70+200; ?>"></canvas>	
	</div>	
	<div class="funclistfooter" onmousedown="resizeStart(event, 3)"></div>
</div>

<div id="window4" name="window" style="width:300px; height:300px;">
	<div class="funclisttitlebar">
		<div id="windowtitle4" onClick="top(4)" onmousedown="dragstart(4)" class="funclisttitle">
		user input
		</div>
		<input type="button" class="closebutton" value="x" onClick="closeWindow(4)" title="close" />
	</div>
	<div id="windowcontent4" class="funclistcontent">
		<?php
		createUserinputList($user_input);
		?>
	</div>
	<div class="funclistfooter" onmousedown="resizeStart(event, 4)"></div>
</div>

<div id="window5" name="window" style="width:300px; height:300px;">
	<div class="funclisttitlebar">
		<div id="windowtitle4" onClick="top(5)" onmousedown="dragstart(5)" class="funclisttitle">
		scanned files and includes
		</div>
		<input type="button" class="closebutton" value="x" onClick="closeWindow(5)" title="close" />
	</div>
	<div id="windowcontent5" class="funclistcontent">
		<div >
			<input type="button" id="filelistbutton" class="button" onclick="showlist('file');minWindow(5, 650);" value="list" style="background:white;color:black;"/>
			<input type="button" id="filegraphbutton" class="button" onclick="showgraph('file');maxWindow(5, 650);" value="graph"/>
			<input type="button" id="filecanvassave" class="button" onclick="saveCanvas('filecanvas', 5)" value="save graph" />
		</div>
		<?php
		createFileList($scanned_files, $file_sinks_count);
		?>
		<div id="canvas5" style="display:none"></div>
		<canvas id="filecanvas" tabindex="0" width="650" height="<?php echo (count($files)/4)*70+200; ?>"></canvas>
	</div>
	<div class="funclistfooter" onmousedown="resizeStart(event, 5)"></div>
</div>		

<div id="funccode" onclick="closeFuncCode()">
	<div id="funccodetitle" onmouseout="closeFuncCode()"></div>
	<div id="funccodecontent"></div>
</div>

<div id="stats" class="stats">
	<table class="textcolor" width="100%">
		<tr>
			<th align="left" style="font-size:22px;padding-left:10px">Result</th>
			<th align="right"><input class="button" type="button" value="x" onClick="document.getElementById('stats').style.display='none';" title="close" /></th>
		</tr>
	</table>	
	<hr />	
	<table class="textcolor" width="100%">	
<?php 
	// output stats
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
			echo '<tr><td nowrap width="160" onmouseover="this.style.color=\'white\';" onmouseout="this.style.color=\'#DFDFDF\';" onClick="showAllCats()" style="cursor:pointer;" title="show all categories">Sum:</td><td>',$count_all,'</td></tr>';
		} else
		{
			echo '<tr><td colspan="2" width="160">No vulnerabilities found.</td></tr>';
		}
	} else
	{
		echo '<tr><td colspan="2">',(($count_matches == 0) ? 'No' : $count_matches),' matches found.</td></tr>';
	}

	echo '</table><hr /><table class="textcolor" width="100%">',
		'<tr><td nowrap width="160" onmouseover="this.style.color=\'white\';" onmouseout="this.style.color=\'#DFDFDF\';" onClick="openWindow(5);eval(document.getElementById(\'filegraph_code\').innerHTML);maxWindow(5, 650);" style="cursor:pointer;" title="open files window">Scanned files:</td><td nowrap colspan="2">',count($files),'</td></tr>';
	if(empty($CONFIG['search']))
	{
		echo '<tr><td nowrap width="160">Include success:</td><td nowrap colspan="2">';
	
		if($count_inc > 0)
		{
			echo ($count_inc_success=$count_inc-$count_inc_fail).'/'.$count_inc, 
			' ('.$round_inc_success=round(($count_inc_success/$count_inc)*100,0).'%)'; 
		} else
		{
			echo 'No includes.';
		}
		
		echo '</td></tr>',
		'<tr><td nowrap>Considered sinks:</td><td nowrap>',count($scan_functions),'</td><td rowspan="4" >';
		if(empty($CONFIG['search']) && $count_all > 0)
		{
			echo '<div class="diagram"><canvas id="diagram" width="80" height="70"></canvas></div>';
		}
		echo '</td></tr>',
		'<tr><td nowrap onmouseover="this.style.color=\'white\';" onmouseout="this.style.color=\'#DFDFDF\';" onClick="openWindow(3);eval(document.getElementById(\'functiongraph_code\').innerHTML);maxWindow(3, 650);" style="cursor:pointer;" title="open functions window">User-defined functions:</td><td nowrap>'.(count($user_functions_offset)-(count($user_functions_offset)>0?1:0)).'</td></tr>',
		'<tr><td nowrap onmouseover="this.style.color=\'white\';" onmouseout="this.style.color=\'#DFDFDF\';" onClick="openWindow(4);" style="cursor:pointer;" title="open userinput window">Unique sources:</td><td nowrap>'.count($user_input).'</td></tr>',
		'<tr><td nowrap>Sensitive sinks:</td><td nowrap>'.(is_array($file_sinks_count) ? array_sum($file_sinks_count) : 0).'</td></tr>',
		'</table><hr />';
		
		// output info gathering
		if( !empty($info) || ($count_inc>0 && $round_inc_success < 75 && !$scan_subdirs && count($files)>1) )
		{
			$info = array_unique($info);
			echo '<table class="textcolor" width="100%">';
			foreach($info as $detail)
			{
				echo '<tr><td width="160">Info:</td><td><small>',$detail,'</small></td></tr>';
			}	
			if($count_inc>0 && $round_inc_success < 75 && !$scan_subdirs && count($files)>1)
			{
				echo '<tr><td width="160">Info:</td><td><small><font color="orange">Your include success is low. Enable <i>subdirs</i> for better filename guesses.</font></small></td></tr>';
			}
			echo '</table><hr />';
		}
	}	
		?>
		<table class="textcolor" width="100%">
		<tr><td nowrap width="160">Scan time:</td><td nowrap><span id="scantime"><?php printf("%.03f seconds", $elapsed); ?></span></td></tr>
	</table>		

</div>
<?php		
		
	@printoutput($output, $CONFIG['treestyle']);	
		
	}
