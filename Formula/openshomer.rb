class Openshomer < Formula
  include Language::Python::Virtualenv

  desc "Autonomous AI Agent Security Engineer (Powered by MuleRun, QoderWork & Qoder)"
  homepage "https://github.com/kavix/OpenShomer"
  url "https://github.com/kavix/OpenShomer/archive/refs/tags/v0.2.0.tar.gz"
  sha256 "e022f28124b3eb11742a3654eb36026ffdc10ec58d7fb40eb9255cb65ec63255"
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
