<?php
/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannesdahse@gmx.de)
			

Copyright (C) 2010 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.		

**/

	###############################  INCLUDES  ################################

	require_once('config/general.php');			// general CONFIG
	require_once('config/sources.php');			// tainted variables and functions
	require_once('config/tokens.php');			// tokens for lexical analysis
	require_once('config/securing.php');			// securing functions
	require_once('config/sinks.php');			// sensitive sinks
	require_once('config/info.php');				// interesting functions
	
	require_once('functions/tokens.php');		// prepare and fix token list
	require_once('functions/scan.php');			// scan for sinks in token list
	// require_once('functions/output.php');		// output scan result
	require_once('functions/search.php');		// search functions
	
	require_once('classes/classes.php'); 		// classes
	
	###############################  MAIN  ####################################
	
	// Handle setup of CONFIG array ...
	//  as this was the _POST array before, we can simply copy all of _POST into CONFIG
	//  if we're being called via the web
	// otherwise
	//  process the command line arguments to setup CONFIG
	$CONFIG = array();
	
	if ('cli' == PHP_SAPI) {
		require_once('functions/parse_cli_args.php');
		$CONFIG = parse_cli();
		$OutputMode = 'text';
	}
	else {
		$OutputMode = 'interactive';
		$CONFIG = array_merge($_POST);
	}
	
	
	// Choose Output Mode & pull in appropriate output functions
	// $OutputMode = 'Dtext';
	switch($OutputMode) {
		case 'text':
			require_once('functions/output_text.php');
			break;
		case 'interactive':	
		default:			
			require_once('functions/output.php');
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
			$data = read_recursiv($location, $scan_subdirs);
			
			if(count($data) > $warnfiles && !isset($CONFIG['ignore_warning']))
				die('warning:'.count($data));
		}	
		else if(is_file($location) && in_array(substr($location, strrpos($location, '.')), $filetypes))
		{
			$data[0] = $location;
		}
		else
		{
			$data = array();
		}
	
		// SCAN
		if(empty($CONFIG['search']))
		{
			$scan_functions = array();
			$user_functions = array();
			$user_functions_offset = array();
			$file_sinks_count = array();
			$user_input = array();
			
			$count_xss=$count_sqli=$count_fr=$count_fa=$count_fi=$count_exec=$count_code=0;
			$count_eval=$count_xpath=$count_ldap=$count_con=$count_other=$count_pop=0;
			$count_inc=$count_inc_fail=0;
			
			$verbosity = isset($CONFIG['verbosity']) ? $CONFIG['verbosity'] : 1;

			if($verbosity != 5)
			{
				switch($CONFIG['vector']) 
				{
					case 'client': 		$scan_functions = $F_XSS;			break;
					case 'code': 		$scan_functions = $F_CODE;			break;
					case 'file_read':	$scan_functions = $F_FILE_READ;		break;
					case 'file_affect':	$scan_functions = $F_FILE_AFFECT;	break;		
					case 'file_include':$scan_functions = $F_FILE_INCLUDE;	break;			
					case 'exec':  		$scan_functions = $F_EXEC;			break;
					case 'database': 	$scan_functions = $F_DATABASE;		break;
					case 'xpath':		$scan_functions = $F_XPATH;			break;
					case 'ldap':		$scan_functions = $F_LDAP;			break;
					case 'connect': 	$scan_functions = $F_CONNECT;		break;
					case 'unserialize':	{
										$scan_functions = array_merge($F_POP,$F_XSS);				
										$F_INTEREST = $F_INTEREST_POP;
										$F_USERINPUT = array('unserialize');
										$verbosity = 2;
										} 
										break;
					case 'all': 
						$scan_functions = array_merge(
							$F_XSS,
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
				$F_USERINPUT = $F_OTHER_INPUT;
				// add file and database functions as tainting functions
				if( $verbosity > 1 && $verbosity < 5 )
				{
					$F_USERINPUT = array_merge($F_OTHER_INPUT, $F_FILE_INPUT, $F_DATABASE_INPUT);
				}
			}	
			
			foreach($data as $file_name)
			{
				$userfunction_secures = false;
				$userfunction_taints = false;
				$scanned_files[$file_name] = scan_file($file_name, $scan_functions, 
				$T_FUNCTIONS, $T_ASSIGNMENT, $T_IGNORE, 
				$T_INCLUDES, $T_XSS, $T_IGNORE_STRUCTURE, $F_INTEREST);
			}
			
		}
		// SEARCH
		else if(!empty($CONFIG['regex']))
		{
			$count_matches = 0;
			$verbosity = 0;
			foreach($data as $file_name)
			{
				searchFile($file_name, $CONFIG['regex']);
			}
		}
	} 
	
	$elapsed = microtime(TRUE) - $start;
	
	################################  RESULT  #################################	
	
// *****************
//  TODO:
//  * rework output to have multiple forms
//    + interactive HTML+JS (current)
//    + static HTML
//    + plain text
//  * Create Abstract Class to handle output based on mode
//  * Move existing output functions into Concrete Class
//  * Create new Concrete class for new output methods
//    eg.  Output_Text::render($data)
//  * Update / Create scan handler for CLI access
//    + perhaps move actual scan to a "core" location & have
//    + main.php and "rips-cli.php" set up variables before calling the core
//  * Wrap the core scan into a class
//  * Add a mechanism to let the class pass data to the output class cleanly
	
	
switch ($OutputMode) {
	case 'text':
		require_once('functions/output_text.php');
		if ('cli' != PHP_SAPI) 
		{
			echo "<pre>\n";
		}
		
		echo "\n", '=================== RESULTS SUMMARY ====================', "\n";

		if(empty($CONFIG['search']))
		{
			$count_all=$count_xss+$count_sqli+$count_fr+$count_fa+$count_fi+$count_exec+$count_code+$count_eval+$count_xpath+$count_ldap+$count_con+$count_other;
			
			if($count_all > 0)
			{
				if($count_code > 0)
					statsRow($NAME_CODE, $count_code, $count_all);
				if($count_exec > 0)	
					statsRow($NAME_EXEC, $count_exec, $count_all);
				if($count_con > 0)	
					statsRow($NAME_CONNECT, $count_con, $count_all);
				if($count_fr > 0)	
					statsRow($NAME_FILE_READ, $count_fr, $count_all);
				if($count_fi > 0)	
					statsRow($NAME_FILE_INCLUDE, $count_fi, $count_all);
				if($count_fa > 0)	
					statsRow($NAME_FILE_AFFECT, $count_fa, $count_all);
				if($count_ldap > 0)	
					statsRow($NAME_LDAP, $count_ldap, $count_all);
				if($count_sqli > 0)	
					statsRow($NAME_DATABASE, $count_sqli, $count_all);
				if($count_xpath > 0)	
					statsRow($NAME_XPATH, $count_xpath, $count_all);
				if($count_xss > 0)	
					statsRow($NAME_XSS, $count_xss, $count_all);
				if($count_other > 0)	
					statsRow($NAME_OTHER, $count_other, $count_all);
				//echo "\n\t\tSum:\t",$count_all,"\n"; 
				printf("   %25s   %5d\n", 'TOTAL', $count_all);
				printf("   %25s   %5d\n", 'Scan Functions', count($scan_functions));
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
			echo "\nScanned Files:          " , count($scanned_files);
			echo "\nInclude success:        " , $is;
			echo "\nConsidered sinks:       " , count($scan_functions);
			echo "\nUser-defined functions: " , (count($user_functions_offset)-(count($user_functions_offset)>0?1:0));
			echo "\nUnique sources:         " , count($user_input);
			echo "\nSensitive sinks:        " , (is_array($file_sinks_count) ? array_sum($file_sinks_count) : 0);
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
			
		printoutput($output, $CONFIG);
		
		if ($CONFIG['outv7y'] > 3) {
			echo "\n============== INCLUDE TREE ===============================\n";
			createFileList($scanned_files);		
			echo "\n===========================================================\n";
		}
		
		//@printoutput($output, $CONFIG); 
		
		echo "\n============== ELAPSED TIME ===============================\n";		
		printf("Scanned %d files in %.03f seconds", count($scanned_files), $elapsed);
		echo "\n===========================================================\n";
		
		if ('cli' != PHP_SAPI) 
		{
			echo "<pre>\n";
		} 
		break;
	case 'interactive':
	default:
		require_once('functions/output.php');
?>	
<div id="window1" name="window" style="width:600px; height:250px;">
	<div class="windowtitlebar">
		<div id="windowtitle1" onClick="top(1)" onmousedown="dragstart(1)" class="windowtitle"></div>
		<input id="maxbutton1" type="button" class="maxbutton" value="&nabla;" onClick="maxWindow(1, 800)" title="maximize" />
		<input type="button" class="closebutton" value="x" onClick="closeWindow(1)" title="close" />
	</div>
	<div id="windowcontent1" class="windowcontent"></div>
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
			<input type="button" id="functiongraphbutton" class="button" onclick="showgraph('function');maxWindow(3, 650);" value="graph" style="background:white;color:black;"/>
			<input type="button" id="functionlistbutton" class="button" onclick="showlist('function');minWindow(3, 650);" value="list" />
			<input type="button" id="functioncanvassave" class="button" onclick="saveCanvas('functioncanvas', 3)" value="save image" />
			<?php  if($verbosity == 5) echo '(graph not available in debug mode)'; ?>
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
			<input type="button" id="filegraphbutton" class="button" onclick="showgraph('file');maxWindow(5, 650);" value="graph" style="background:white;color:black;"/>
			<input type="button" id="filelistbutton" class="button" onclick="showlist('file');minWindow(5, 650);" value="list" />
			<input type="button" id="filecanvassave" class="button" onclick="saveCanvas('filecanvas', 5)" value="save graph" />
		</div>
		<?php
			createFileList($scanned_files, $file_sinks_count);		
		?>
		<div id="canvas5" style="display:none"></div>
		<canvas id="filecanvas" tabindex="0" width="650" height="<?php echo (count($data)/4)*70+200; ?>"></canvas>
	</div>
	<div class="funclistfooter" onmousedown="resizeStart(event, 5)"></div>
</div>		

<div id="funccode" onmouseout="closeFuncCode()">
	<div id="funccodetitle"></div>
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
		$count_all=$count_xss+$count_sqli+$count_fr+$count_fa+$count_fi+$count_exec+$count_code+$count_eval+$count_xpath+$count_ldap+$count_con+$count_other+$count_pop;
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
			if($count_other > 0)	
				statsRow(11, $NAME_OTHER, $count_other, $count_all);
			if($count_pop > 0)	
				statsRow(12, $NAME_POP, $count_pop, $count_all);	
			echo '<tr><td nowrap width="160" onmouseover="this.style.color=\'white\';" onmouseout="this.style.color=\'#DFDFDF\';" onClick="showAllCats()" style="cursor:pointer;" title="show all categories">Sum:</td><td>',$count_all,'</td></tr>';
			echo '<tr><td nowrap width="160" onmouseover="this.style.color=\'white\';" onmouseout="this.style.color=\'#DFDFDF\';" onClick="showAllCats()" style="cursor:pointer;" title="show all categories">Scan Functions:</td><td>',count($scan_functions),'</td></tr>';

		} else
		{
			echo '<tr><td colspan="2" width="160">No vulnerabilities found.</td></tr>';
		}
	} else
	{
		echo '<tr><td colspan="2">',(($count_matches == 0) ? 'No' : $count_matches),' matches found.</td></tr>';
	}

	echo '</table><hr /><table class="textcolor" width="100%">',
		'<tr><td nowrap width="160">Scanned files:</td><td nowrap colspan="2">',count($data),'</td></tr>';
	if(empty($CONFIG['search']))
	{
		echo '<tr><td nowrap width="160">Include success:</td><td nowrap colspan="2">';
	
		if($count_inc > 0)
		{
			echo ($count_inc_success=$count_inc-$count_inc_fail).'/'.$count_inc, 
			' ('.round(($count_inc_success/$count_inc)*100,0).'%)'; 
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
		'<tr><td nowrap>User-defined functions:</td><td nowrap>'.(count($user_functions_offset)-(count($user_functions_offset)>0?1:0)).'</td></tr>',
		'<tr><td nowrap>Unique sources:</td><td nowrap>'.count($user_input).'</td></tr>',
		'<tr><td nowrap>Sensitive sinks:</td><td nowrap>'.(is_array($file_sinks_count) ? array_sum($file_sinks_count) : 0).'</td></tr>',
		'</table><hr />';
		
		// output info gathering
		if(!empty($info))
		{
			$info = array_unique($info);
			echo '<table class="textcolor" width="100%">';
			foreach($info as $detail)
			{
				echo '<tr><td width="160">Info:</td><td><small>',$detail,'</small></td></tr>';
			}	
			echo '</table><hr />';
		}
	}	
		?>
		<table class="textcolor" width="100%">
		<tr><td nowrap width="160">Scan time:</td><td nowrap><?php printf("%.03f seconds", $elapsed); ?></td></tr>
	</table>		

</div>

<?php 

	// scan result
	@printoutput($output, $CONFIG); 
}

