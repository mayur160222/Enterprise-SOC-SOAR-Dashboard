import { Component, type ReactNode, type ErrorInfo } from 'react';
import { AlertOctagon, RotateCw } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error safely caught by ErrorBoundary:', error, errorInfo);
  }

  private handleReload = () => {
    this.setState({ hasError: false, error: null });
    window.location.reload();
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-slate-950 text-white flex items-center justify-center p-6">
          <div className="max-w-md w-full bg-slate-900 border border-red-500/30 rounded-2xl p-6 shadow-2xl text-center">
            <div className="w-14 h-14 bg-red-500/10 rounded-xl flex items-center justify-center mx-auto mb-4">
              <AlertOctagon className="w-8 h-8 text-red-400" />
            </div>
            <h2 className="text-xl font-bold mb-2">SOC Dashboard Notice</h2>
            <p className="text-sm text-slate-400 mb-4">
              A rendering issue was prevented. Click below to reload the dashboard cleanly.
            </p>
            {this.state.error && (
              <pre className="text-xs bg-slate-950 p-3 rounded-lg text-red-300 font-mono text-left overflow-auto max-h-32 mb-4 border border-slate-800">
                {this.state.error.message}
              </pre>
            )}
            <button
              onClick={this.handleReload}
              className="inline-flex items-center gap-2 px-4 py-2 bg-sky-500 hover:bg-sky-400 text-white text-sm font-medium rounded-lg transition-colors"
            >
              <RotateCw className="w-4 h-4" />
              Reset & Reload Dashboard
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

