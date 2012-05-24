<?php
/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannes.dahse@rub.de)
			
			
Copyright (C) 2012 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.	

**/	


	// tokens to string for comments
	function tokenstostring($tokens)
	{
		$output = '';
		for($i=0;$i<count($tokens);$i++)
		{
			$token = $tokens[$i];
			if (is_string($token))
			{	
				if($token === ',' || $token === ';')
					$output .= "$token ";
				else if(in_array($token, Tokens::$S_SPACE_WRAP) || in_array($token, Tokens::$S_ARITHMETIC))
					$output .= " $token ";
				else	
					$output .= $token;
			}	
			else if(in_array($token[0], Tokens::$T_SPACE_WRAP) || in_array($token[0], Tokens::$T_OPERATOR) || in_array($token[0], Tokens::$T_ASSIGNMENT))
				$output .= " {$token[1]} ";
			else
				$output .= $token[1];
		}
		return $output;
	}
	
	
		// detect vulnerability type given by the PVF name
	// note: same names are used in help.php!
	function getVulnNodeTitle($func_name)
	{
		if(isset($GLOBALS['F_XSS'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_XSS'];  }
		else if(isset($GLOBALS['F_HTTP_HEADER'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_HTTP_HEADER'];  }		
		else if(isset($GLOBALS['F_DATABASE'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_DATABASE'];  }	
		else if(isset($GLOBALS['F_FILE_READ'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_FILE_READ'];  }
		else if(isset($GLOBALS['F_FILE_AFFECT'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_FILE_AFFECT']; }		
		else if(isset($GLOBALS['F_FILE_INCLUDE'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_FILE_INCLUDE'];  }	
		else if(isset($GLOBALS['F_CONNECT'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_CONNECT']; }		
		else if(isset($GLOBALS['F_EXEC'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_EXEC'];  }
		else if(isset($GLOBALS['F_CODE'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_CODE']; }
		else if(isset($GLOBALS['F_XPATH'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_XPATH'];	 } 
		else if(isset($GLOBALS['F_LDAP'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_LDAP'];}
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
		else if(isset($GLOBALS['F_HTTP_HEADER'][$func_name])) 
		{	$GLOBALS['count_header']++; }
		else if(isset($GLOBALS['F_DATABASE'][$func_name])) 
		{	$GLOBALS['count_sqli']++; }	
		else if(isset($GLOBALS['F_FILE_READ'][$func_name])) 
		{	$GLOBALS['count_fr']++; }
		else if(isset($GLOBALS['F_FILE_AFFECT'][$func_name])) 
		{	$GLOBALS['count_fa']++; }		
		else if(isset($GLOBALS['F_FILE_INCLUDE'][$func_name])) 
		{	$GLOBALS['count_fi']++; }	
		else if(isset($GLOBALS['F_CONNECT'][$func_name])) 
		{	$GLOBALS['count_con']++; }
		else if(isset($GLOBALS['F_EXEC'][$func_name])) 
		{	$GLOBALS['count_exec']++; }
		else if(isset($GLOBALS['F_CODE'][$func_name])) 
		{	$GLOBALS['count_code']++; }
		else if(isset($GLOBALS['F_XPATH'][$func_name])) 
		{	$GLOBALS['count_xpath']++; } 
		else if(isset($GLOBALS['F_LDAP'][$func_name])) 
		{	$GLOBALS['count_ldap']++; }	
		else if(isset($GLOBALS['F_POP'][$func_name])) 
		{	$GLOBALS['count_pop']++; }
		else if(isset($GLOBALS['F_OTHER'][$func_name])) 
		{	$GLOBALS['count_other']++; } // :X
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
	
	