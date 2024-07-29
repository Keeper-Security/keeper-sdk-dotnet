using System;
using System.ComponentModel;
using System.Linq;
using System.Windows.Input;
using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Sync;

namespace WPFSample
{
    public interface IPassword
    {
        string Password { get; set; }
    }

    public class CommandHandler : ICommand
    {
        private Action _action;
        private Func<bool> _canExecute;

        public CommandHandler(Action action, Func<bool> canExecute = null)
        {
            _action = action;
            _canExecute = canExecute;
        }

        public event EventHandler CanExecuteChanged
        {
            add { CommandManager.RequerySuggested += value; }
            remove { CommandManager.RequerySuggested -= value; }
        }

        public bool CanExecute(object parameter)
        {
            return _canExecute?.Invoke() ?? true;
        }

        public void Execute(object parameter)
        {
            _action?.Invoke();
        }
    }

    public class CommandParameterHandler : ICommand
    {
        private Action<object> _action;
        private Func<bool> _canExecute;

        public CommandParameterHandler(Action<object> action, Func<bool> canExecute = null)
        {
            _action = action;
            _canExecute = canExecute;
        }

        public event EventHandler CanExecuteChanged
        {
            add { CommandManager.RequerySuggested += value; }
            remove { CommandManager.RequerySuggested -= value; }
        }

        public bool CanExecute(object parameter)
        {
            return _canExecute?.Invoke() ?? true;
        }

        public void Execute(object parameter)
        {
            _action?.Invoke(parameter);
        }
    }

    public class BaseViewModel : INotifyPropertyChanged, IDisposable
    {
        public virtual void Dispose()
        {
        }

        public void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
        public event PropertyChangedEventHandler PropertyChanged;
    }

    public interface ILoginStep
    {
        bool CanGoNext();
    }

    public class UsernameLoginStep : ILoginStep
    {
        private string dataCenter;

        public string Username { get; set; }
        public string DataCenter
        {
            get
            {
                return dataCenter;
            }
            set
            {
                dataCenter = value;
            }
        }
        public bool CanGoNext()
        {
            return !string.IsNullOrEmpty(Username);
        }
    }

    public class DeviceApproveActionButton
    {
        public DeviceApproveActionButton(DeviceApprovalChannel channel)
        {
            Channel = channel;
        }

        public DeviceApprovalChannel Channel { get; }

        public string Title
        {
            get
            {
                switch (Channel)
                {
                case DeviceApprovalChannel.Email:
                    return "Send Email";
                case DeviceApprovalChannel.KeeperPush:
                    return "Send Keeper Push";
                case DeviceApprovalChannel.TwoFactorAuth:
                    return "Use Two-Factor Method";
                default:
                    return Channel.ToString();
                }
            }
        }
    }

    public class ApproveDeviceMethods : ILoginStep
    {
        public ApproveDeviceMethods(DeviceApprovalChannel[] channels)
        {
            DeviceApprovalChannels = channels;
            DeviceApproveActionButtons = DeviceApprovalChannels
                .Select(x => new DeviceApproveActionButton(x)).ToArray();
        }


        public ICommand DeviceApproveCommand { get; internal set; }
        public DeviceApproveActionButton[] DeviceApproveActionButtons { get; }
        internal DeviceApprovalChannel[] DeviceApprovalChannels { get; }
        public bool CanGoNext()
        {
            return false;
        }
    }

    public class VerificationCodeStep : ILoginStep
    {
        public VerificationCodeStep(DeviceApprovalChannel channel)
        {
            DeviceApproval = channel;
        }

        public VerificationCodeStep(TwoFactorChannel channel)
        {
            TwoFactor = channel;
        }

        internal DeviceApprovalChannel? DeviceApproval = null;
        internal TwoFactorChannel? TwoFactor = null;

        public string Username { get; set; }
        public string Title
        {
            get
            {
                if (DeviceApproval.HasValue)
                {
                    return "Device Approval";
                }
                else if (TwoFactor.HasValue)
                {
                    return "Two Factor Authentication";
                }
                else
                {
                    return null;
                }
            }
        }

        public string Description
        {
            get
            {
                if (DeviceApproval.HasValue)
                {
                    switch (DeviceApproval.Value)
                    {
                    case DeviceApprovalChannel.Email:
                        return $"Enter verification code sent to {Username}";
                    case DeviceApprovalChannel.TwoFactorAuth:
                        return "Enter the code in your TFA application";
                    }
                }
                else if (TwoFactor.HasValue)
                {
                    return "Enter the code in your TFA application";
                }
                return null;
            }
        }


        public string Code { get; set; }

        public bool CanGoNext()
        {
            return !string.IsNullOrEmpty(Code);
        }
    }

    public class EnterMasterPasswordStep : ILoginStep, IPassword
    {
        public EnterMasterPasswordStep(string username)
        {
            Username = username;
            Password = "";
        }

        public string Username { get; set; }
        public string Password { get; set; }

        public bool CanGoNext()
        {
            return !string.IsNullOrEmpty(Password);
        }
    }

    public class LoginFinishedStep : ILoginStep
    {
        private bool _isSuccess;
        public LoginFinishedStep(bool isSuccess) {
            _isSuccess = isSuccess;
        }

        public string Status => _isSuccess ? "Logged In" : "Login failure";
        public bool CanGoNext()
        {
            return false;
        }
    }

    public class LoginViewModel : BaseViewModel, IAuthSyncCallback
    {
        private AuthSync _auth;
        private ILoginStep stepData;
        private string errorText;

        public LoginViewModel(AuthSync auth)
        {

            _auth = auth;
            _auth.UiCallback = this;
            OnNextStep();

            NextCommand = new CommandHandler(NextClicked, CanClickNext);
            CancelCommand = new CommandHandler(Cancel);

        }

        public ICommand NextCommand { get; }
        public ICommand CancelCommand { get; }


        public ILoginStep StepData
        {
            get
            {
                return stepData;
            }

            internal set
            {
                stepData = value;
                OnPropertyChanged("StepData");
            }
        }

        public string ErrorText
        {
            get => errorText; internal set
            {
                errorText = value;
                OnPropertyChanged("ErrorText");
            }
        }

        public void OnNextStep()
        {
            if (_auth.Step is ReadyToLoginStep rtls)
            {
                if (!(StepData is UsernameLoginStep))
                {
                    var uls = new UsernameLoginStep
                    {
                        Username = _auth.Storage.LastLogin
                    };
                    if (!string.IsNullOrEmpty(_auth.Storage.LastServer))
                    {
                        if (_auth.Storage.LastServer.EndsWith("keepersecurity.com"))
                        {
                            uls.DataCenter = "US";
                        }
                        else if (_auth.Storage.LastServer.EndsWith("keepersecurity.eu"))
                        {
                            uls.DataCenter = "EU";
                        }
                        else if (_auth.Storage.LastServer.EndsWith("keepersecurity.ca"))
                        {
                            uls.DataCenter = "CA";
                        }
                        else if (_auth.Storage.LastServer.EndsWith("keepersecurity.com.au"))
                        {
                            uls.DataCenter = "AU";
                        }
                    }
                    StepData = uls;
                }
            }
            else if (_auth.Step is DeviceApprovalStep das)
            {
                if (!(StepData is ApproveDeviceMethods) && !(StepData is VerificationCodeStep))
                {
                    StepData = new ApproveDeviceMethods(das.Channels)
                    {
                        DeviceApproveCommand = new CommandParameterHandler((parameter) =>
                        {
                            if (!(parameter is DeviceApprovalChannel channel)) return;
                            das.SendPush(channel);
                            if (channel == DeviceApprovalChannel.KeeperPush) return;

                            var step = new VerificationCodeStep(channel)
                            {
                                Username = _auth.Username
                            };
                            StepData = step;
                        })
                    };
                }
            }
            else if (_auth.Step is TwoFactorStep tfs)
            {
                if (!(StepData is VerificationCodeStep))
                {
                    var channel = TwoFactorChannel.Other;
                    foreach (var ch in tfs.Channels)
                    {
                        if (ch != TwoFactorChannel.SecurityKey)
                        {
                            channel = ch;
                            break;
                        }
                    }
                    if (channel == TwoFactorChannel.TextMessage)
                    {
                        tfs.SendPush(TwoFactorPushAction.TextMessage);
                    }
                    StepData = new VerificationCodeStep(channel);
                }
            }
            else if (_auth.Step is PasswordStep ps)
            {
                if (!(StepData is EnterMasterPasswordStep))
                {
                    StepData = new EnterMasterPasswordStep(_auth.Username);
                }
            }
            else if (_auth.Step is ConnectedStep) {
                StepData = new LoginFinishedStep(true);
            }
            else if (_auth.Step is ErrorStep es)
            {
                StepData = new LoginFinishedStep(false);
                ErrorText = es.Message;
            }
        }

        private async void NextClicked()
        {
            ErrorText = null;

            try
            {
                if (StepData is UsernameLoginStep uls)
                {
                    if (_auth.Step.State != AuthState.NotConnected)
                    {
                        _auth.Cancel();
                    }

                    await _auth.Login(uls.Username);
                }
                else if (StepData is VerificationCodeStep ads && _auth.Step is DeviceApprovalStep das)
                {
                    await das.SendCode(ads.DeviceApproval.Value, ads.Code);
                }
                else if (StepData is VerificationCodeStep tfas && _auth.Step is TwoFactorStep tfs)
                {
                    tfs.Duration = TwoFactorDuration.EveryLogin;
                    await tfs.SendCode(tfas.TwoFactor.Value, tfas.Code);
                }
                else if (StepData is EnterMasterPasswordStep emps && _auth.Step is PasswordStep ps)
                {
                    try
                    {
                        await ps.VerifyPassword(emps.Password);
                    }
                    catch (KeeperAuthFailed)
                    {
                        ErrorText = "Invalid email or password combination, please re-enter.";
                    }
                }
                else
                {
                    OnNextStep();
                }
            }
            catch (Exception e)
            {
                ErrorText = e.Message;
            }

            OnPropertyChanged("ErrorText");
        }


        public bool CanClickNext()
        {
            return StepData?.CanGoNext() ?? false;
        }
        private void Cancel()
        {
            _auth.Cancel();
        }

        public override void Dispose()
        {
            _auth.UiCallback = null;
            base.Dispose();
        }
    }
}
