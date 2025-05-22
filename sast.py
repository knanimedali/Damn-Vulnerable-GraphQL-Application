# --- START OF FILE sast.py ---

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import subprocess
import json
import webbrowser
import os
from datetime import datetime
import re
import threading
import shutil
import tempfile
import html # For escaping output in HTML report
import sys # For CLI sys.exit

# Define supported languages and their file extensions
# *** REMOVED: Ruby, Go, Swift, Kotlin ***
SUPPORTED_LANGUAGES = {
    "Python": [".py"],
    "JavaScript": [".js", ".jsx", ".ts", ".tsx"],
    "Java": [".java"],
    "C/C++": [".c", ".cpp", ".cc", ".h", ".hpp"],
    "PHP": [".php"],
    "C#": [".cs"], # Kept C# for now as DevSkim is integrated
}

# Mapping of language to tools
# *** REMOVED entries for: Ruby, Go, Swift, Kotlin ***
LANGUAGE_TOOLS = {
    "Python": ["bandit", "semgrep", "pylint"],
    "JavaScript": ["semgrep", "eslint", "jshint"],
    "Java": ["semgrep", "spotbugs", "pmd"], # Placeholders - require build context usually
    "C/C++": ["semgrep", "cppcheck", "flawfinder"],
    "PHP": ["semgrep", "phpcs"],
    "C#": ["semgrep", "devskim"], # Devskim is the main tool for C# here
}

# Track which languages we've already checked for tools
checked_languages = set()

# Get all supported file extensions
def get_all_file_extensions():
    all_extensions = []
    for language, extensions in SUPPORTED_LANGUAGES.items():
        all_extensions.extend(extensions)
    return all_extensions

# Detect language from file extension
def detect_language(file_path):
    _, ext = os.path.splitext(file_path)
    ext_lower = ext.lower()
    # print(f"DEBUG detect_language: file='{file_path}', ext='{ext_lower}'") # DEBUG
    if not ext_lower: return None
    for language, extensions in SUPPORTED_LANGUAGES.items():
        if ext_lower in extensions:
            # print(f"DEBUG detect_language: Found language '{language}' for '{file_path}'") # DEBUG
            return language
    # print(f"DEBUG detect_language: No language for '{file_path}'") # DEBUG
    return None

# --- SAST Analysis Functions ---
# (These run_*_analysis functions are from your provided file and are assumed correct for this fix)
# Function to run Bandit analysis (Python)
def run_bandit_analysis(file_path):
    temp_output_file = f"bandit_temp_{os.path.basename(file_path)}.json"
    try:
        cmd = ["bandit", "-f", "json", "-o", temp_output_file, file_path]
        print(f"Running Bandit command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        output_data = {}
        error_msg = None
        if os.path.exists(temp_output_file):
            try:
                with open(temp_output_file, "r", encoding='utf-8') as f: content = f.read()
                if content and content.strip(): output_data = json.loads(content)
                elif result.returncode != 0: error_msg = f"Bandit failed (Code {result.returncode}) and produced empty output file."
            except json.JSONDecodeError as e: error_msg = f"Failed to parse Bandit JSON file: {e}"
            finally: os.remove(temp_output_file) # Cleanup
        elif result.stdout and result.stdout.strip(): # Fallback
             try: output_data = json.loads(result.stdout)
             except json.JSONDecodeError as e: error_msg = f"Failed to parse Bandit JSON from stdout: {e}"
        elif result.returncode != 0: error_msg = f"Bandit failed (Code {result.returncode}) with no output."

        if error_msg:
             print(error_msg); error_details = error_msg
             if result.stderr: error_details += f". Stderr: {result.stderr.strip()}"
             return {"error": error_details, "results": []}
        else:
             if "results" not in output_data and "errors" not in output_data: print(f"Warning: Bandit output structure unexpected."); return {"results": []}
             return output_data
    except FileNotFoundError: print("Error: 'bandit' cmd not found."); return {"error": "'bandit' not found", "results": []}
    except Exception as e: print(f"Error running Bandit: {e}");
    if os.path.exists(temp_output_file): os.remove(temp_output_file) ; return {"error": str(e), "results": []}

# Function to run Semgrep analysis (multiple languages)
def run_semgrep_analysis(file_path, language=None):
    try:
        cmd = ["semgrep", "--json"]
        config_added = False
        if language:
             lang_config_name = language.lower().replace("c/c++", "cpp").replace("c#", "csharp")
             packs = [f"p/{lang_config_name}"]
             packs.extend(["p/secrets", "p/security-audit", "p/owasp-top-ten"]) # Generic packs
             for pack in packs: cmd.extend(["--config", pack]); config_added = True
        if not config_added: cmd.extend(["--config", "auto"])
        cmd.append(file_path)
        print(f"Running Semgrep command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.stdout and result.stdout.strip():
            try:
                 output_data = json.loads(result.stdout)
                 if "results" in output_data: return output_data
                 else: print(f"Warning: Semgrep JSON missing 'results'."); return {"error": "Semgrep fmt unexpected.", "results":[]}
            except json.JSONDecodeError as e: print(f"Error parsing Semgrep JSON: {e}"); return {"error": f"Semgrep JSON decode error: {e}", "results": []}
        else:
            error_info = f"Semgrep produced no JSON (Exit: {result.returncode})."
            if result.stderr and result.stderr.strip(): error_info += f" Stderr: {result.stderr.strip()}"
            print(error_info); return {"error": error_info, "results": []}
    except FileNotFoundError: print("Error: 'semgrep' not found."); return {"error": "'semgrep' not found", "results": []}
    except Exception as e: print(f"Error running Semgrep: {e}"); return {"error": str(e), "results": []}

# Function to run SpotBugs analysis (Java) - Placeholder
def run_spotbugs_analysis(file_path):
    print("Warning: SpotBugs analysis placeholder executed.")
    return {"results": [], "error": "SpotBugs integration placeholder."}

# Function to run PMD analysis (Java) - Placeholder
def run_pmd_analysis(file_path):
    print("Warning: PMD analysis placeholder executed.")
    return {"results": [], "error": "PMD integration placeholder."}

# Function to run Pylint analysis (Python)
def run_pylint_analysis(file_path):
    print("Running Pylint analysis.")
    try:
        cmd = ["pylint", "--output-format=json", "--disable=C,R,W,I", file_path]
        print(f"Running Pylint command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.stdout and result.stdout.strip():
             try: pylint_issues = json.loads(result.stdout); return {"results": pylint_issues}
             except json.JSONDecodeError as e: print(f"Error parsing Pylint JSON: {e}"); return {"error": f"Pylint JSON err: {e}", "results": []}
        else:
            error_msg=f"Pylint failed/no JSON (Exit:{result.returncode})."; print(error_msg+(f" Stderr:{result.stderr.strip()}" if result.stderr else "")); return {"error":error_msg, "results":[]}
    except FileNotFoundError: print("Error:'pylint' not found."); return {"error":"'pylint' not found", "results":[]}
    except Exception as e: print(f"Error running Pylint:{e}"); return {"error":str(e),"results":[]}

# Function to run ESLint analysis (JavaScript)
def run_eslint_analysis(file_path):
    print("Running ESLint analysis (requires eslint.config.js).")
    try:
        cmd = ["eslint", "--format=json", file_path]
        print(f"Running ESLint command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.stdout and result.stdout.strip():
             try: eslint_data = json.loads(result.stdout); return {"results": eslint_data}
             except json.JSONDecodeError as e: print(f"Error parsing ESLint JSON: {e}"); return {"error":f"ESLint JSON err:{e}", "results":[]}
        else:
            error_msg=f"ESLint failed/no JSON (Exit:{result.returncode})."; print(error_msg+(f" Stderr:{result.stderr.strip()}" if result.stderr else "")); return {"error":error_msg, "results":[]}
    except FileNotFoundError: print("Error:'eslint' not found."); return {"error":"'eslint' not found","results":[]}
    except Exception as e: print(f"Error running ESLint:{e}"); return {"error":str(e),"results":[]}

# Function to run JSHint analysis (JavaScript)
def run_jshint_analysis(file_path):
    print("Running JSHint analysis.")
    xml_output_str = None
    try:
        cmd = ["jshint", "--reporter=checkstyle", file_path]
        print(f"Running JSHint command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        issues = []; error_msg = None
        if result.stdout and result.stdout.strip():
             xml_output_str = result.stdout
             try:
                 if not xml_output_str.startswith('<?xml'): raise ValueError("Not Checkstyle XML")
                 pattern = r'<error.*?line="(\d+)".*?severity="(\w+)".*?message="(.*?)".*?source="(.*?)?".*?/>'
                 matches = re.findall(pattern, xml_output_str, re.DOTALL | re.IGNORECASE)
                 for line, sev_str, msg_raw, src_rule in matches: issues.append({'file': file_path, 'line': line, 'severity': sev_str.lower(), 'description': html.unescape(msg_raw.replace('"','"')), 'code': src_rule})
                 if not matches and '<error' in xml_output_str: print("Warn: JSHint <error> tags found but regex not match.")
                 if not issues and result.returncode != 0 : error_msg = f"JSHint exit({result.returncode}) but 0 issues parsed."
             except ValueError as ve: error_msg = f"JSHint XML parse err: {ve}. XML: {xml_output_str[:200]}"
             except Exception as parse_err: error_msg = f"Error JSHint XML parse: {parse_err}."
        elif result.returncode != 0: error_msg = f"JSHint failed(Exit:{result.returncode})."
        if error_msg: print(error_msg) ;
        if xml_output_str and "XML" not in error_msg: error_msg = (error_msg or "") + f" XML start:{xml_output_str[:100]}" # Append if error_msg is None
        return {"results": issues, "error": error_msg}
    except FileNotFoundError: print("Error: 'jshint' not found."); return {"error":"'jshint' not found","results":[]}
    except Exception as e: print(f"Error running JSHint:{e}"); return {"error":str(e),"results":[]}

# Function to run cppcheck analysis (C/C++)
def run_cppcheck_analysis(file_path):
    print("Running cppcheck analysis."); stderr_str=None
    try:
        cmd = ["cppcheck", "--enable=all", "--xml", file_path]; print(f"Running cppcheck: {' '.join(cmd)}")
        result=subprocess.run(cmd,capture_output=True,text=True,check=False)
        issues=[];error_msg=None
        if result.stderr and result.stderr.strip():
             stderr_str=result.stderr
             try:
                 if not stderr_str.startswith('<?xml'):error_msg=f"cppcheck stderr not XML:{stderr_str[:200]}"
                 elif '<error id=' not in stderr_str: pass # No findings
                 else:
                    pattern=r'<error id="([^"]+)" severity="(\w+)" msg="([^"]+)".*?<location file="([^"]+)" line="(\d+)"/>'
                    matches=re.findall(pattern,stderr_str,re.DOTALL)
                    for rid,s_str,msg,xml_f,line in matches:
                        try:
                            if os.path.samefile(xml_f,file_path):issues.append({'file':file_path,'line':line,'severity':s_str,'description':html.unescape(msg),'code':rid})
                        except FileNotFoundError: pass # Skip unmatched files
                    if not matches and result.returncode !=0:error_msg=f"cppcheck exit({result.returncode}) but 0 parsed."
             except Exception as e: error_msg=f"Err parse cppcheck XML:{e}"
        elif result.returncode !=0: error_msg=f"cppcheck fail(Exit:{result.returncode}) no stderr XML."
        if error_msg: print(error_msg);
        if stderr_str and "Stderr" not in (error_msg or ""):error_msg=(error_msg or "") +f" Stderr:{stderr_str[:100]}"
        return {"results":issues,"error":error_msg}
    except FileNotFoundError:print("Error:'cppcheck' not found.");return{"error":"'cppcheck' not found","results":[]}
    except Exception as e: print(f"Error cppcheck:{e}");return{"error":str(e),"results":[]}

# Function to run flawfinder analysis (C/C++)
def run_flawfinder_analysis(file_path):
    print("Running flawfinder analysis."); stdout_str=None
    try:
        cmd = ["flawfinder","--csv",file_path]; print(f"Running flawfinder: {' '.join(cmd)}")
        result=subprocess.run(cmd,capture_output=True,text=True,check=False)
        issues=[];error_msg=None
        if result.stdout and result.stdout.strip():
            stdout_str=result.stdout.strip();lines=stdout_str.split('\n')
            if len(lines)>1 and re.match(r'^File,Line,Column,.*Level,.*Name,',lines[0]):
                try:
                    for line in lines[1:]:
                        if not line.strip():continue
                        parts=line.split(',');m_parts=6
                        if len(parts)>=m_parts:
                            ff_f,ff_l,ff_lvl,_,ff_name,ff_warn=parts[0],parts[1],parts[2],parts[4],parts[5]
                            if ff_f==file_path or os.path.basename(ff_f)==os.path.basename(file_path):
                                try:lvl_int=int(ff_lvl);sev='high' if lvl_int>=4 else 'medium' if lvl_int>=2 else 'low'
                                except ValueError: sev='low'
                                issues.append({'file':file_path,'line':ff_l,'severity':sev,'description':f"{ff_name}:{ff_warn.strip()}",'code':ff_name})
                except Exception as e:error_msg=f"Error parsing flawfinder CSV:{e}"
            elif result.returncode!=0 or not stdout_str.startswith('File,Line,Column'):error_msg=f"Flawfinder unexpected output(lines={len(lines)}).Exit={result.returncode}.Output:{stdout_str[:200]}"
        elif result.returncode !=0: error_msg=f"flawfinder fail(Exit:{result.returncode}).Stderr:{result.stderr.strip()}"
        if error_msg: print(error_msg)
        return {"results":issues,"error":error_msg}
    except FileNotFoundError:print("Error:'flawfinder' not found.");return{"error":"'flawfinder' not found","results":[]}
    except Exception as e:print(f"Error flawfinder:{e}");return{"error":str(e),"results":[]}

# Function to run PHPcs analysis (PHP)
def run_phpcs_analysis(file_path):
    print("Running PHPCS analysis.");
    try:
        cmd=["phpcs","--report=json",file_path]; print(f"Running PHPCS: {' '.join(cmd)}")
        result=subprocess.run(cmd,capture_output=True,text=True,check=False)
        data={};error_msg=None
        if result.stdout and result.stdout.strip():
             try:data=json.loads(result.stdout); assert 'totals' in data and 'files' in data
             except (json.JSONDecodeError, AssertionError) as e: error_msg=f"PHPCS JSON format err:{e}"
        elif result.returncode!=0: error_msg=f"PHPCS fail(Exit:{result.returncode}).Stderr:{result.stderr.strip()}"
        if error_msg: print(error_msg); return {"error":error_msg,"results":[]}
        else:
            issues=[]
            if data.get('totals',{}).get('errors',0)>0 or data.get('totals',{}).get('warnings',0)>0:
                for fname,fdata in data.get('files',{}).items():
                    for msg in fdata.get('messages',[]):sev='high' if msg.get('type','').lower()=='error' else 'medium'; issues.append({'file':fname,'line':msg.get('line'),'severity':sev,'description':msg.get('message'),'code':msg.get('source'),'source':'PHPCS'})
            return {"results":issues}
    except FileNotFoundError: print("Error:'phpcs' not found."); return {"error":"'phpcs' not found","results":[]}
    except Exception as e: print(f"Error PHPCS:{e}"); return {"error":str(e),"results":[]}

# Function to run DevSkim analysis (C#)
def run_devskim_analysis(file_path):
    """Runs DevSkim. Requires .NET Runtime installed (e.g., sudo apt install dotnet-runtime-8.0)."""
    print(f"DevSkim scan on:{file_path}");devskim_exec=os.path.expanduser("~/.dotnet/tools/devskim")
    if not os.path.isfile(devskim_exec): msg=f"DevSkim tool not found:{devskim_exec}.Use 'dotnet tool install...'";print(msg);return{"error":msg,"results":[]}
    sarif_path = None
    try:
        tmpdir=tempfile.gettempdir();sarif_path=os.path.join(tmpdir,f"devskim_{os.getpid()}.sarif")
        cmd=[devskim_exec,"analyze",file_path,"-o",sarif_path,"-f","sarif"];print(f"Run DevSkim:{' '.join(cmd)}")
        result=subprocess.run(cmd,capture_output=True,text=True,check=False)
        print(f"DevSkim ExitCode:{result.returncode}");
        if result.stderr: print(f"DevSkim STDERR:\n{result.stderr}")
        if os.path.exists(sarif_path) and os.path.getsize(sarif_path)>0:
             print(f"Reading DevSkim SARIF:{sarif_path}")
             with open(sarif_path,'r',encoding='utf-8') as f:
                try: sarif_data=json.load(f); assert "runs" in sarif_data; print("Parsed DevSkim SARIF."); return {"results":sarif_data,"error":None}
                except Exception as e: msg=f"SARIF parse fail:{e}"; print(msg); return {"results":None,"error":msg}
        else:
             err=f"DevSkim SARIF missing/empty:{sarif_path}.Exit={result.returncode}.";
             if result.stderr and ".NET location: Not found" in result.stderr: err+="\n\n>>> .NET Runtime Missing! Install 'dotnet-runtime-8.0' <<<"
             elif result.stderr: err+=f" Stderr:{result.stderr.strip()[:300]}"
             print(err); return {"results":None,"error":err}
    except FileNotFoundError: print(f"Error:DevSkim exec fail (FileNotFoundError) at {devskim_exec}"); return {"error":"'devskim' execution failed","results":[]}
    except Exception as e: print(f"Critical DevSkim err:{e}"); return {"results":None,"error":str(e)}
    finally: # Cleanup
        if sarif_path and os.path.exists(sarif_path):
            try: os.remove(sarif_path)
            except OSError as e: print(f"Warn:Failed DevSkim temp cleanup {sarif_path}:{e}")

# --- Utility Functions ---
def normalize_severity(severity_input):
    if severity_input is None: return 'low'
    s=str(severity_input).lower()
    if s in ['critical','fatal','blocker','error','high']: return 'high'
    if s in ['medium','warning','major','serious']: return 'medium'
    if s.isdigit():l=int(s);return 'high' if l<=2 else 'medium' if l<=3 else 'low'
    return 'low'

def count_severities(all_results):
    counts={'critical':0,'high':0,'medium':0,'low':0}
    for r in all_results: counts[normalize_severity(r.get('severity','low'))]+=1
    return counts

def generate_results_rows(all_results):
    rows=""
    for r in all_results:
        fp=r.get('file','N/A')or"N/A";fn=os.path.basename(fp)if fp!='N/A'else'N/A';ln=r.get('line','N/A')
        sev_o=r.get('severity','low');tool=r.get('source','Unknown');desc=str(r.get('description','N/A'));code=str(r.get('code','N/A'))
        sev_c=normalize_severity(sev_o);sev_d=sev_c.capitalize()
        rows+=f"""<tr><td>{html.escape(fn)}</td><td>{html.escape(str(ln))}</td><td><span class="severity {sev_c}">{sev_d}</span></td><td>{html.escape(tool)}</td><td>{html.escape(desc)}</td><td><pre>{html.escape(code)}</pre></td></tr>"""
    return rows

def normalize_results(tool_results_dict, language):
    all_normalized_results=[]
    for tool_name, tool_data in tool_results_dict.items():
        if isinstance(tool_data, dict) and tool_data.get("error"): print(f"Skip norm for {tool_name} due to error: {tool_data['error']}."); continue
        if not tool_data: continue
        try:
            if tool_name == "bandit" and "results" in tool_data:
                 [all_normalized_results.append({'file':i.get('filename'),'line':i.get('line_number'),'severity':i.get('issue_severity'),'description':f"({i.get('test_id')}) {i.get('issue_text')}",'code':i.get('code'),'source':'Bandit'}) for i in tool_data.get("results",[])]
            elif tool_name == "semgrep" and "results" in tool_data:
                 [all_normalized_results.append({'file':i.get('path'),'line':i.get('start',{}).get('line'),'severity':i.get('extra',{}).get('metadata',{}).get('impact',i.get('extra',{}).get('metadata',{}).get('severity',i.get('severity','INFO'))),'description':f"({i.get('check_id')}) {i.get('extra',{}).get('message')}",'code':i.get('extra',{}).get('lines'),'source':'Semgrep'}) for i in tool_data.get("results",[])]
            elif tool_name in ["pmd","spotbugs"] and isinstance(tool_data,dict) and "results" in tool_data: [all_normalized_results.append({'file':i.get('file'),'line':i.get('line'),'severity':i.get('severity'),'description':i.get('description'),'code':i.get('code'),'source':tool_name.capitalize()}) for i in tool_data.get("results",[])]
            elif tool_name == "pylint" and isinstance(tool_data,dict) and "results" in tool_data: [all_normalized_results.append({'file':i.get('path'),'line':i.get('line'),'severity':'high','description':f"[{i.get('symbol')}]({i.get('message-id')}) {i.get('message')}",'code':i.get('symbol'),'source':'Pylint'}) for i in tool_data.get("results",[])]
            elif tool_name == "eslint" and isinstance(tool_data,dict) and "results" in tool_data: [all_normalized_results.append({'file':f.get('filePath'),'line':i.get('line'),'severity':('high' if i.get('severity')==2 else 'medium'),'description':f"({i.get('ruleId')}) {i.get('message')}",'code':i.get('ruleId'),'source':'ESLint'}) for f in tool_data.get("results",[]) for i in f.get('messages',[])]
            elif tool_name == "jshint" and isinstance(tool_data,dict) and "results" in tool_data: [all_normalized_results.append({'file':i.get('file'),'line':i.get('line'),'severity':('high' if 'error' in i.get('severity','') else 'medium'),'description':i.get('description'),'code':i.get('code'),'source':'JSHint'}) for i in tool_data.get("results",[])]
            elif tool_name in ["cppcheck","flawfinder","phpcs"] and isinstance(tool_data,dict) and "results" in tool_data: [all_normalized_results.append({'file':i.get('file'),'line':i.get('line'),'severity':i.get('severity'),'description':i.get('description'),'code':i.get('code'),'source':tool_name.capitalize()}) for i in tool_data.get("results",[])]
            elif tool_name == "devskim" and isinstance(tool_data,dict) and tool_data.get("results"):
                 for run in tool_data["results"].get("runs",[]):
                     tool_name_sarif = run.get("tool", {}).get("driver", {}).get("name", "DevSkim")
                     for r in run.get("results", []):
                         lvl=r.get('level','note');sev='high' if lvl=='error' else 'medium' if lvl=='warning' else 'low'; msg_txt=r.get("message",{}).get("text","N/A");rid=r.get("ruleId","N/A");
                         fp,ln,sn="N/A","N/A","N/A"; locs=r.get("locations",[])
                         if locs: pL=locs[0].get("physicalLocation");
                         if pL:uri=pL.get("artifactLocation",{}).get("uri","N/A");fp=uri.replace("file:///","").replace("file:/","")
                         if os.name=='nt' and fp.startswith('/') and len(fp)>2 and fp[2]==':':fp=fp[1:];reg=pL.get("region",{});ln=reg.get("startLine","N/A");sn=reg.get("snippet",{}).get("text","N/A");
                         all_normalized_results.append({'file':fp,'line':ln,'severity':sev,'description':f"({rid}) {msg_txt}",'code':sn,'source':tool_name_sarif})
            else:
                 if tool_name in LANGUAGE_TOOLS.get(language, []): print(f"Warn: No normalization logic for tool '{tool_name}' data type: {type(tool_data)}")
        except Exception as e: print(f"ERROR normalizing {tool_name}: {e}"); import traceback; traceback.print_exc()
    return all_normalized_results

SCRIPT_DIR=os.path.dirname(os.path.abspath(__file__)); TEMPLATE_PATH=os.path.join(SCRIPT_DIR,"index.html")
def generate_report(files_data, language_counts, scan_type="SAST"):
    all_results=[]; count=0
    for fp, (t_res, lang) in files_data.items():
        if t_res and lang:
            try: all_results.extend(normalize_results(t_res,lang)); count+=1
            except Exception as e:print(f"ERR norm {fp}:{e}")
    print(f"Aggregated {len(all_results)} issues from {count} files for report.")
    sev_counts=count_severities(all_results); rows_html=generate_results_rows(all_results)
    num_in=len(files_data);target_name=os.path.basename(next(iter(files_data))) if num_in==1 else f"Folder({count}/{num_in} analyzed)" if count!=num_in else f"Folder({num_in} files)";target_esc=html.escape(target_name)
    is_gui_available = os.environ.get('DISPLAY') is not None # Check once for report generation
    try:
        with open(TEMPLATE_PATH,"r",encoding="utf-8") as f: tmpl=f.read()
    except Exception as e: msg=f"Template read err({TEMPLATE_PATH}):{e}"; print(msg)
    if is_gui_available and 'messagebox' in globals() and messagebox: messagebox.showerror("Error",msg); return None
    scan_dt=datetime.now().strftime("%Y-%m-%d %H:%M:%S");reps={"file_name":target_esc,"scan_date":scan_dt,"total_issues":str(len(all_results)),"critical":str(sev_counts['critical']),"high":str(sev_counts['high']),"medium":str(sev_counts['medium']),"low":str(sev_counts['low']),"results_rows":rows_html}
    report_content=tmpl; [report_content:=report_content.replace(f"{{{k}}}",str(v)) for k,v in reps.items()]
    try: rdir=os.path.join(SCRIPT_DIR,"reports");os.makedirs(rdir,exist_ok=True);ts=datetime.now().strftime("%Y%m%d%H%M%S");s_tgt=re.sub(r'[<>:"/\\|?*\s]+','_',target_name)[:50];rfn=f"sast_report_{s_tgt}_{ts}.html";rpath=os.path.join(rdir,rfn)
    except Exception as e: msg=f"Path err:{e}";print(msg)
    if is_gui_available and 'messagebox' in globals() and messagebox: messagebox.showerror("Error",msg);return None
    try:
        with open(rpath,"w",encoding="utf-8") as f:f.write(report_content);print(f"SAST report:{rpath}");return rpath
    except Exception as e: msg=f"Write report fail {rpath}:{e}";print(msg);
    if is_gui_available and 'messagebox' in globals() and messagebox:messagebox.showerror("Error",msg);return None

def check_tools_installed(language, status_label=None):
    # GUI availability check once at the beginning
    is_gui_available = os.environ.get('DISPLAY') is not None

    if language in checked_languages: return True
    tools_to_check = LANGUAGE_TOOLS.get(language, [])
    if not tools_to_check: return True # No tools configured for this language

    print(f"Checking tool availability for {language}: {', '.join(tools_to_check)}")
    missing_tools = []
    problem_tools = [] # For tools that exist but fail specific checks (e.g., timeout, bad exit)

    for tool in tools_to_check:
        cmd = None
        try:
            if tool == "devskim":
                devskim_path = os.path.expanduser("~/.dotnet/tools/devskim")
                cmd = [devskim_path, "--version"] if os.path.isfile(devskim_path) else None
                if cmd is None: raise FileNotFoundError(f"Devskim not found at {devskim_path}") # Specific failure for DevSkim path
            elif tool == "bandit": cmd = ["bandit", "-h"]
            elif tool in ["semgrep", "pylint", "eslint", "jshint", "cppcheck", "flawfinder", "phpcs"]: # Simplified list for existing tools
                cmd = [tool, "--version"]
            # Note: SpotBugs, PMD, GoSec, SwiftLint were removed from LANGUAGE_TOOLS earlier
            # If they were re-added, their check commands would need to be here.
            else:
                print(f"Warning: No specific check command defined for tool '{tool}'. Assuming it's handled if listed or is a placeholder.")
                continue # Skip the subprocess check for these

            process = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=10)
        except FileNotFoundError:
            print(f"Tool '{tool}' check failed: Command/Executable not found.")
            missing_tools.append(tool)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as proc_err:
            print(f"Tool '{tool}' check command executed but failed or timed out: {proc_err}")
            problem_tools.append(f"{tool} (check command issue)")
        except Exception as e:
            print(f"Unexpected error checking tool '{tool}': {e}")
            problem_tools.append(f"{tool} (unexpected check error)")

    summary_parts = []
    if missing_tools: summary_parts.append(f"Missing: {', '.join(missing_tools)}")
    if problem_tools: summary_parts.append(f"Problems with: {', '.join(problem_tools)}")
    summary = ". ".join(summary_parts)

    if summary: # If there were any issues
        print(f"Tool Check Summary ({language}): {summary}")
        full_message_for_popup = f"Tool checks for {language} had issues:\n{summary}\n\nEnsure tools are installed correctly and in PATH.\nAnalysis may be incomplete."
        if status_label:
            status_display = summary[:40] + "..." if len(summary) > 40 else summary
            status_label.config(text=f"Tool check ({language}): {status_display}")
        if is_gui_available and 'messagebox' in globals() and messagebox:
            try: messagebox.showwarning(f"Tool Check Issues ({language})", full_message_for_popup)
            except tk.TclError as e: print(f"Note: Could not show Tk messagebox for tool check: {e}")

    is_critical_tool_failure = bool(missing_tools)
    checked_languages.add(language)
    if not is_critical_tool_failure:
        log_msg = f"Tool check OK for {language}"
        if summary: log_msg += f" (Problems noted: {summary})"
        print(log_msg)
    return not is_critical_tool_failure

def analyze_file(file_path, root=None, status_label=None):
    language = detect_language(file_path);tool_results={}
    if not language: return None, None
    if not check_tools_installed(language,status_label): return None, language # Blocked
    if status_label:status_label.config(text=f"Analyze:{os.path.basename(file_path)}");
    if root: root.update()
    tools_cfg=LANGUAGE_TOOLS.get(language,[]);
    if not tools_cfg:print(f"No tools defined for {language}.");return {},language
    for tool in tools_cfg:
        print(f"-> Run '{tool}' on '{os.path.basename(file_path)}'")
        result=None
        try:
            run_func_name = f"run_{tool}_analysis"
            run_func = globals().get(run_func_name)
            if run_func: result = run_func(file_path, language) if tool == "semgrep" else run_func(file_path)
            else: print(f"   Warn: No {run_func_name} func. Skipping.") ; continue
            if result: tool_results[tool] = result
            if isinstance(result,dict) and result.get("error"): print(f"   Tool '{tool}' err:{result['error']}")
        except Exception as e: msg=f"CRIT dispatch err'{tool}':{e}";print(msg);tool_results[tool]={"error":msg}
    return tool_results, language

def scan_single_file(status_label=None, root=None):
    supported=get_all_file_extensions();ftypes=[("Code"," ".join(f"*{e}" for e in supported)),("All","*.*")]
    fp=filedialog.askopenfilename(title="Select File for SAST",filetypes=ftypes)
    if not fp:
        if status_label:status_label.config(text="Scan cancelled.");return
    def run_scan():
        fdata={};lcounts={};performed=False
        if status_label:status_label.config(text="Start scan...");
        if root: root.update()
        results,lang = analyze_file(fp,root,status_label)
        if lang and results is not None:fdata[fp]=(results,lang);lcounts[lang]=1;performed=True
        elif not lang and status_label:
            msg = f"Unsupported file: {os.path.basename(fp)}"
            status_label.config(text=msg)
            if os.environ.get('DISPLAY') is not None and 'messagebox' in globals() and messagebox: messagebox.showinfo("Unsupported",msg)
            else: print(msg)
        if not performed:
            if status_label and (not lang or results is None): # Ensure status is updated
                 status_label.config(text="Scan finished. No analysis performed (check logs).")
            return
        if status_label:status_label.config(text="Generating report...");
        if root: root.update()
        report=generate_report(fdata,lcounts)
        if report:
            status=f"Done:{os.path.basename(report)}";disp=status[:97]+"..." if len(status)>100 else status
            if status_label:status_label.config(text=disp)
            try: webbrowser.open('file://'+os.path.realpath(report))
            except Exception as e: print(f"No report open:{e}")
            if os.environ.get('DISPLAY') is not None and 'messagebox' in globals() and messagebox: messagebox.showinfo("Report","Scan done.Report:\n"+report)
            else: print(f"Report available at: {report}")
        else:
            if status_label:status_label.config(text="Scan done.Report FAIL.")
    threading.Thread(target=run_scan,daemon=True).start()

def scan_folder(status_label=None, root=None):
    folder=filedialog.askdirectory(title="Select Folder for SAST")
    if not folder:
        if status_label:status_label.config(text="Scan cancelled.");return
    def run_scan():
        fdata={};lcounts={};supported=[];skipped_tools=0; analyzed_ok=0
        if status_label:status_label.config(text="Finding files...");
        if root: root.update()
        exclude_dirs={'.git','.svn','node_modules','__pycache__','venv','env','.venv','target','build','dist','.settings','.github'}
        for cur,dirs,files in os.walk(folder):
            dirs[:]=[d for d in dirs if d not in exclude_dirs]
            for fname in files:
                 fpath=os.path.join(cur,fname)
                 # *** CORRECTED LIST APPEND LOGIC FOR GUI SCAN FOLDER ***
                 if detect_language(fpath):
                     supported.append(fpath)
        total_files=len(supported)
        if total_files==0:
            msg="No supported files found in folder.";
            if status_label:status_label.config(text=msg)
            if os.environ.get('DISPLAY') is not None and 'messagebox' in globals() and messagebox: messagebox.showinfo("Scan Folder",msg)
            else: print(msg)
            return
        if status_label:status_label.config(text=f"Found {total_files}.Analyzing...");
        if root: root.update()
        for i,fp in enumerate(supported):
            fname=os.path.basename(fp)
            if i%max(1,total_files//10)==0 or i+1==total_files:
                  if status_label:status_label.config(text=f"Analyze {i+1}/{total_files}:{fname[:25]}");
                  if root: root.update()
            results,lang = analyze_file(fp,root=None,status_label=status_label)
            if lang and results is not None:fdata[fp]=(results,lang);lcounts[lang]=lcounts.get(lang,0)+1;analyzed_ok+=1
            elif lang and results is None:skipped_tools+=1
        summary_msg=f"Analysis done.Analyzed:{analyzed_ok}/{total_files}." + (f" ({skipped_tools} skipped)." if skipped_tools else "")
        if status_label:status_label.config(text=summary_msg);
        if root:root.update()
        if not fdata:
             print(summary_msg)
             if status_label:status_label.config(text=summary_msg)
             if os.environ.get('DISPLAY') is not None and 'messagebox' in globals() and messagebox: messagebox.showinfo("Scan Complete",summary_msg)
             else: print(f"CLI Info:{summary_msg}")
             return
        if status_label:status_label.config(text="Generating report...");
        if root:root.update()
        report_path=generate_report(fdata,lcounts)
        if report_path:
             final_status=f"Scan done:{os.path.basename(report_path)}";disp=final_status[:97]+"..." if len(final_status)>100 else final_status
             if status_label:status_label.config(text=disp)
             try: webbrowser.open('file://'+os.path.realpath(report_path))
             except Exception as e: print(f"No report open:{e}")
             if os.environ.get('DISPLAY') is not None and 'messagebox' in globals() and messagebox: messagebox.showinfo("Report","Scan done.Report:\n"+report_path)
             else: print(f"Report available at: {report_path}")
        else:
            if status_label:status_label.config(text="Scan done but report FAIL.")
    threading.Thread(target=run_scan,daemon=True).start()


# --- CLI Entry Point ---
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SAST Scanner CLI. Scans a folder.")
    parser.add_argument("folder_path", help="Path to the folder to scan.")
    args = parser.parse_args()
    if not os.path.isdir(args.folder_path):print(f"Error: Path '{args.folder_path}' not a directory.");sys.exit(1)
    print(f"SAST CLI: Starting scan on folder: {args.folder_path}")
    class DummyStatusLabel:
        def config(self, text=""): print(f"CI Status: {text}")
    dummy_label = DummyStatusLabel()
    def run_cli_scan_direct(folder_to_scan, status_lbl):
        files_data={};lang_counts={};supported_files=[]
        if status_lbl: status_lbl.config(text=f"CI: Finding files in {folder_to_scan}...")
        exclude_dirs={'.git','.svn','node_modules','__pycache__','venv','env','.venv','target','build','dist','.settings','.github'}
        for cur,dirs,files in os.walk(folder_to_scan):
            dirs[:]=[d for d in dirs if d not in exclude_dirs]
            for fname in files:
                 fpath=os.path.join(cur,fname)
                 # *** CORRECTED LIST APPEND LOGIC FOR CLI SCAN ***
                 if detect_language(fpath):
                     supported_files.append(fpath)
        total_files=len(supported_files)
        if total_files==0:msg="CI: No supported files.";status_lbl.config(text=msg);print(msg);return None
        status_lbl.config(text=f"CI: Found {total_files} files. Analyzing...")
        processed=0;skipped=0;analyzed_ok=0
        for i,fp in enumerate(supported_files):
             fname_base=os.path.basename(fp)
             status_lbl.config(text=f"CI: Analyzing {i+1}/{total_files}: {fname_base[:30]}")
             results, lang = analyze_file(fp,root=None,status_label=status_lbl)
             if lang and results is not None: files_data[fp]=(results,lang);lang_counts[lang]=lang_counts.get(lang,0)+1;analyzed_ok+=1
             elif lang and results is None: skipped+=1
        summary=f"CI: Analysis complete. Analyzed:{analyzed_ok}/{total_files}."+(f"({skipped} skipped)." if skipped else "")
        status_lbl.config(text=summary); print(summary)
        if not files_data: print("CI: No files for report.");return None
        status_lbl.config(text="CI: Generating report...")
        report_p = generate_report(files_data,lang_counts)
        if report_p: print(f"CI: SAST Report: {report_p}"); return report_p
        else: print("CI: SAST Report gen FAILED."); return None
    report_file_path = run_cli_scan_direct(args.folder_path, dummy_label)
    sys.exit(0 if report_file_path else 1)

# --- END OF FILE sast.py ---