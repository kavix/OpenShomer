class Openshomer < Formula
  include Language::Python::Virtualenv

  desc "Autonomous AI Agent Security Engineer (Powered by MuleRun, QoderWork & Qoder)"
  homepage "https://github.com/kavix/OpenShomer"
  url "https://github.com/kavix/OpenShomer/archive/refs/tags/v0.3.0.tar.gz"
  sha256 "e2301e52af3ae0516918942478f1e691c1e006aa5ac34e2da451b8e8efa732a9"
  license "Apache-2.0"
  head "https://github.com/kavix/OpenShomer.git", branch: "main"

  depends_on "python@3.11"

  def install
    virtualenv_install_with_resources
  end

  test do
    system bin/"openshomer", "version"
  end
end
