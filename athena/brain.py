"""
The "Brain" class handles most of Hey Athena's processing.
To listen for input, use ``brain.inst.run()``
"""
from __future__ import print_function

import traceback
import os
import re
import yaml

from athena import settings, stt, tts, apis, mods, log
from athena.shell_command_guard import guard as shell_guard



class ShellSafetyError(Exception):
    """Raised when shell_command_guard blocks execution of text.

    Attributes:
        guard_result: Full dict from shell_command_guard.guard()
        text: The text that was blocked
    """
    def __init__(self, text, guard_result):
        self.text = text
        self.guard_result = guard_result
        summary = guard_result.get('summary', 'Shell safety check failed')
        recommendations = guard_result.get('recommendations', [])
        detail = summary
        if recommendations:
            detail += ' Recommendations: ' + '; '.join(recommendations)
        super().__init__(detail)

inst = None

try:
    input = raw_input  # Python 2 fix
except NameError:
    pass


def init():
    global inst
    inst = Brain()


class Brain:
    def __init__(self, greet_user=True):
        """
        First look for and initialize APIs in the "api_library" folder.
        Then prompt the user to log in.
        Next verify that the user's .yml file is configured for each API.
        If an API's required configuration variables are not found,
        then the API is disabled.
        Next it finds and loads modules in the "modules" folder.
        Lastly, it initializes the STT engine.

        Use "from athena.apis import api_lib" & "api_lib['(api_name_key)']"
        to access instances of APIs.
        """

        apis.find_apis()
        self.login()

        apis.verify_apis(self.user)
        apis.list_apis()

        mods.find_mods()
        mods.list_mods()

        if greet_user:
            self.greet()
        stt.init()
        tts.init()

        self.quit_flag = False
        self.state_tracker = StateTracker()

    def find_users(self):
        """ Returns a list of available user strings """
        self.users = []
        for file in os.listdir(settings.USERS_DIR):
            if file.endswith('.yml'):
                with open(os.path.join(settings.USERS_DIR, file)) as f:
                    user = yaml.safe_load(f)
                    self.users.append(user['user_api']['username'])
        return self.users

    def verify_user_exists(self):
        """ Verify that at least 1 user exists """
        self.find_users()
        if not self.users:
            print('~ No users found. Please create a new user.\n')
            import athena.user_config as cfg
            cfg.generate()
            self.find_users()

    def load_user(self, username):
        """ Load (username).yml data into the user """
        with open(os.path.join(settings.USERS_DIR, username+'.yml'), 'r') as f:
            self.user = yaml.safe_load(f)
            log.debug('Logged in as: '+self.user['user_api']['username'])

    def login(self):
        """ Prompts a user to login (if more than one available) """
        self.verify_user_exists()
        if len(self.users) == 1:
            self.load_user(self.users[0])
            return

        print('~ Users: ', str(self.users)[1:-1])
        username = ''
        while username not in self.users:
            username = input('\n~ Username: ')
            if username not in self.users:
                print('\n~ Please enter a valid username')
                continue
        self.load_user(username)

    def greet(self):
        """ Greet the user """
        print(r"  _    _                      _   _                      ")
        print(r" | |  | |                /\  | | | |                     ")
        print(r" | |__| | ___ _   _     /  \ | |_| |__   ___ _ __   __ _ ")
        print(r" |  __  |/ _ \ | | |   / /\ \| __| '_ \ / _ \ '_ \ / _` |")
        print(r" | |  | |  __/ |_| |  / ____ \ |_| | | |  __/ | | | (_| |")
        print(r" |_|  |_|\___|\__, | /_/    \_\__|_| |_|\___|_| |_|\__,_|")
        print(r"               __/ |                                     ")
        print(r"              |___/                                      ")
        if apis.api_lib['user_api'].name():
            print('\n~ Hey there, '+apis.api_lib['user_api'].name()+'!\n')
        else:
            print('\n~ Hello, what can I do for you today?\n')
        print('~ Try asking:')
        print('  - "Athena (double beep) what\'s the weather like in DFW?"')
        print('  - "Athena (double beep) what is the capital of Tanzania?"')
        print('  - "Athena (double beep) open facebook.com"\n')

    def check_shell_safety(self, text):
        """Pre-flight shell safety check using shell_command_guard.

        Returns guard result dict. Raises ShellSafetyError if text
        appears to be shell-intended but fails safety checks.
        Prose-only text passes through without blocking.
        """
        result = shell_guard(text)
        classification = result['classification']['classification']

        # Block prompt injection regardless of shell classification
        if result['prompt_paste_detected']['is_prompt_paste']:
            raise ShellSafetyError(text, result)

        # Prose-only text is not shell-intended pass through
        if classification == 'prose_only':
            return result

        # Shell-intended text: check safety
        shell_intended = {
            'executable_command', 'heredoc', 'inline_python',
            'shell_plan', 'mixed_unsafe'
        }
        if classification in shell_intended and not result['safe_to_execute']:
            raise ShellSafetyError(text, result)

        # Safe shell text with warnings log but proceed
        if result.get('recommendations'):
            for rec in result['recommendations']:
                log.info('[shell-guard] ' + rec)

        return result

    def execute_tasks(self, mod, text):
        """ Executes a module's task queue """
        # Pre-flight shell safety check
        self.check_shell_safety(text)
        for task in mod.task_queue:
            try:
                # Record task execution start
                if hasattr(self, 'state_tracker'):
                    self.state_tracker.record_task_execution(
                        mod.name, 
                        task.__class__.__name__, 
                        success=True
                    )
                
                # Execute the task
                task.action(text)
                
                # Record successful execution
                if hasattr(self, 'state_tracker'):
                    self.state_tracker.record_task_execution(
                        mod.name, 
                        task.__class__.__name__, 
                        success=True,
                        result="Task executed successfully"
                    )
                
                if task.greedy:
                    break
                    
            except Exception as e:
                # Record failure
                if hasattr(self, 'state_tracker'):
                    self.state_tracker.record_task_execution(
                        mod.name, 
                        task.__class__.__name__, 
                        success=False,
                        error=str(e)
                    )
                    self.state_tracker.set_error(f"Task execution failed: {e}")
                
                # Re-raise if critical
                if task.greedy:
                    raise
    
    def routing_safety_check(self, text):
        """Early routing-layer guard for obviously unsafe text.

        Blocks prompt injection, protected path violations, and mixed
        prose+commands BEFORE module sorting/selection. Safe shell and
        prose pass through for normal routing.

        Returns True if safe to route, raises ShellSafetyError if blocked.
        """
        result = shell_guard(text)
        classification = result["classification"]["classification"]

        # Block prompt injection before routing
        if result["prompt_paste_detected"]["is_prompt_paste"]:
            raise ShellSafetyError(text, result)

        # Block protected path violations before routing
        if not result["protected_violations"]["safe"]:
            raise ShellSafetyError(text, result)

        # Block mixed unsafe (prose+commands) before routing -
        # this text should not be treated as normal conversation
        if classification == "mixed_unsafe":
            raise ShellSafetyError(text, result)

        # Prose, safe shell, heredocs, plans pass through for normal routing
        return True

    def execute_mods(self, text):
        """ Executes the modules in prioritized order """
        # Early routing-layer guard
        self.routing_safety_check(text)

        if len(self.matched_mods) <= 0:
            tts.speak(settings.NO_MODULES)
            return

        self.matched_mods.sort(key=lambda mod: mod.priority, reverse=True)

        normal_mods = []
        greedy_mods = []
        greedy_flag = False
        priority = 0
        for mod in self.matched_mods:
            if greedy_flag and mod.priority < priority:
                break
            if mod.greedy:
                greedy_mods.append(mod)
                greedy_flag = True
                priority = mod.priority
            else:
                normal_mods.append(mod)

        if len(greedy_mods) == 1:
            normal_mods.append(greedy_mods[0])
            # Record selected module in state tracker
            if hasattr(self, "state_tracker"):
                self.state_tracker.record_selected_module(greedy_mods[0])
        elif len(greedy_mods) > 1:
            if 0 < len(normal_mods):
                print('\n~ Matched mods (non-greedy): '+str([mod.name for mod in normal_mods])[1:-1]+'\n')
            m = self.mod_select(greedy_mods)
            if not m:
                return
            normal_mods.append(m)
        for mod in normal_mods:
            self.execute_tasks(mod, text)

    def mod_select(self, mods):
        """ Prompt user to specify which module to use to respond """
        print('\n~ Which module (greedy) would you like me to use to respond?')
        print('~ Choices: '+str([mod.name for mod in mods])[1:-1]+'\n')
        mod_select = input('> ')

        for mod in mods:
            if re.search('^.*\\b'+mod.name+'\\b.*$',  mod_select, re.IGNORECASE):
                return mod
        log.info('No module name found.')

    def pre_match_safety_check(self, text):
        """Pre-match guard: blocks unsafe text before module matching.

        Rejects prompt injection, protected path violations, and mixed
        prose+commands BEFORE any module matching or scoring. Prose and
        safe shell pass through for normal matching.
        """
        result = shell_guard(text)
        classification = result["classification"]["classification"]

        # Block prompt injection before matching
        if result["prompt_paste_detected"]["is_prompt_paste"]:
            raise ShellSafetyError(text, result)

        # Block protected path violations before matching
        if not result["protected_violations"]["safe"]:
            raise ShellSafetyError(text, result)

        # Block mixed unsafe before matching
        if classification == "mixed_unsafe":
            raise ShellSafetyError(text, result)

        # Prose, safe shell, heredocs, plans pass through
        return True

    def match_mods(self, text):
        """ Attempts to match a modules and their tasks """
        # Pre-match guard: reject unsafe text before module matching
        self.pre_match_safety_check(text)

        self.matched_mods = []
        for mod in mods.mod_lib:
            if not mod.enabled:
                continue
            """ Find matched tasks and add to module's task queue """
            mod.task_queue = []
            for task in mod.tasks:
                if task.match(text):
                    mod.task_queue.append(task)
                    if task.greedy:
                        break

            """ Add modules with matched tasks to list """
            if len(mod.task_queue):
                self.matched_mods.append(mod)

    def error(self):
        """ Inform the user that an error occurred """
        tts.speak(settings.ERROR)
        text = input('Continue? (Y/N) ')
        # response = stt.active_listen()
        if 'y' in text.lower():
            log.error(traceback.format_exc())

    def quit(self):
        self.quit_flag = True

    def run(self):
        """ Listen for input, match the modules and respond """
        while True:
            if self.quit_flag:
                break
            try:
                if settings.USE_STT:
                    stt.listen_keyword()
                    text = stt.active_listen()
                else:
                    text = input('> ')
                if not text:
                    log.info('No text input received.')
                    continue
                else:
                    log.info("'"+text+"'")

                self.match_mods(text)
                # Record matched modules
                self.state_tracker.record_matched_modules(self.matched_mods)
                self.execute_mods(text)
                # Save state after execution
                self.state_tracker.save_state()
            except OSError as e:
                if 'Invalid input device' in str(e):
                    log.error(settings.NO_MIC+'\n')
                    settings.USE_STT = False
                    continue
                else:
                    raise Exception
            except (EOFError, KeyboardInterrupt):
                log.info('Shutting down...')
                break
            except:
                log.error("(runtime error)")
                self.error()

        log.info('Arrivederci.')
